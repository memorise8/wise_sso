# Phase 7 qualification runner

## Exact FastAPI candidate image

`ops/phase7/build-exact-image.sh` is the guarded source-to-image entry point. Pass an
explicit full commit ID in either check-only or build mode:

```sh
./ops/phase7/build-exact-image.sh --check-only <expected-40-character-HEAD>
./ops/phase7/build-exact-image.sh --build <expected-40-character-HEAD>
```

The guard accepts a standalone checkout or a correctly cross-linked Git worktree, requires
the complete worktree and index to equal that commit, and rejects replacement, alternate,
partial-clone, bare, injected Git, and unsafe worktree metadata. It hashes the pinned HEAD
blob listing for `Dockerfile`, `pyproject.toml`, `uv.lock`, `README.md`, and every tracked
file below `src/`. Dockerfile and base-image parsing use only that pinned private HEAD
snapshot, never mutable worktree bytes. Local/common and enabled worktree-scoped Git
configuration are read without following includes, case-normalized, and checked for
partial-clone, promisor, and alternate object routing. `include.path` and
`includeIf.*.path` are rejected in both scopes, so external config files are never trusted.
Before any external source tool runs, the guard rejects option-injection
variables (including `TAR_OPTIONS`) and re-executes itself with a minimal cleared
environment.

Build mode currently validates the exact private source context and then unconditionally
returns `INCOMPLETE: CONTROLLED_TOOLCHAIN_REQUIRED`. No Docker command is invoked and no
image qualification claim is emitted. A future build path requires a checked-in, reviewed
toolchain lock plus an isolated daemon collector; Docker self-reporting is not an
authentication boundary. Consequently this guard currently makes no claim that an image
was built offline or that a Docker endpoint could not mutate external resources. Ambient
Git/Docker routing variables and alternate `PATH` values are rejected. `--check-only`
validates and hashes only pinned source/Git material; it reports Docker trust as
`NOT_CHECKED` and makes no claim about the Docker CLI, daemon, socket, or locally cached
base.

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

Only a schema-version `2` manifest is considered for aggregation. Every gate entry pins its
topology and run ID, evidence-relative directory and deterministic aggregate
SHA-256, source revision and Git tree object, separate Express and FastAPI
application-tree SHA-256 values, separate Express and FastAPI lock SHA-256
values, the common schema and configuration SHA-256 values, and separate exact
Express and FastAPI immutable image IDs. The finalizer derives the source values
from the explicit absolute, clean, non-symlink `--repo` worktree. It checks
`HEAD`, `HEAD^{tree}`, and the following exact tracked input sets:

- Express application: every tracked file below `auth-server/src/`,
  `auth-server/public/`, and `auth-server/prisma/migrations/`, plus
  `auth-server/package.json` and `auth-server/tsconfig.json`. The Prisma schema
  remains in the separate schema partition.
- FastAPI application: every tracked file below `fastapi-auth-server/src/`, plus
  `fastapi-auth-server/pyproject.toml` and `fastapi-auth-server/README.md`.
- Express and FastAPI locks: `auth-server/package-lock.json` and
  `fastapi-auth-server/uv.lock`, respectively.
- Schema: `auth-server/prisma/schema.prisma`.
- Runtime configuration: both runtimes' `.dockerignore`, `.env.example`,
  `Dockerfile`, and compose file (`docker-compose.yml` or
  `docker-compose.dev.yml`).

Each set uses the evidence aggregate algorithm below, with repository-relative
paths. The finalizer pins one `sourceRevision`, reads its recursive tree and
blob objects, and hashes those immutable blob bytes; it never hashes mutable
worktree bytes. HEAD is rechecked after derivation and the worktree must remain
clean. Consequently revision, tree object, and every input aggregate describe
the same commit even if worktree bytes are transiently changed and restored.

Git is invoked with pinned worktree and normal `.git` directory descriptors, an
explicit `--git-dir`/`--work-tree`, and a minimal environment that discards
caller `GIT_DIR`, `GIT_WORK_TREE`, common/object/index/config paths, alternates,
ceiling, discovery, and related `GIT_CONFIG*` injection. Linked worktrees, bare
repositories, symlinked or unexpected Git metadata, and alternate object stores
are refused. Object replacement is disabled with `GIT_NO_REPLACE_OBJECTS=1`,
and any pinned `refs/replace/*` is refused before resolving HEAD, its tree, or
blobs. Thus arbitrary self-consistent manifest/bundle hashes, repository
A/B environment redirection, and a global Express/FastAPI field swap are
refused against the named runtime-specific repository hashes. Lock, schema, and
configuration inputs are deliberately represented separately.
Named fields preserve the Express/FastAPI pairing, so exchanging their order is
mixed provenance rather than an equivalent group.

Those values in the manifest are not trusted. Each gate must attach
`provenanceEvidencePath` and `provenanceEvidenceSha256` for an exact versioned
JSON document governed by `ops/phase7/qualification-provenance.schema.json`.
The provenance file must be inside that gate's hashed bundle and repeat the
exact gate ID, topology, run ID, revision, tree object, application trees,
locks, schema, configuration, and image IDs. Every repeated value is derived
from the attachment and cross-checked against the manifest before group
equality is evaluated. Unknown or missing fields are refused.

Each provenance document also binds `collectorAttestationSha256` to a distinct
hashed `collectorAttestationEvidencePath`. The exact current attachment format
is documented by `qualification-collector-attestation.schema.json` and records
only `status=UNVERIFIED`. It cannot authenticate Docker image identity. No
checked-in controlled collector and independently pinned collector verification
mechanism exists yet, so the finalizer unconditionally adds
`controlled-collector-required`. Self-asserted booleans, identifiers, image
digests, or attachment hashes cannot remove that reason.

The manifest and every attached or aggregated input must be single-link regular
non-symlink files, and every path is confined below the explicit repository
evidence root. Stable inode, size, link count, modification time, and change
time are checked around reads; bundle directory metadata and the aggregate are
rechecked after attachments are evaluated. Attachment roles—provenance,
collector attestation, gate result, cleanup, Express-before, and Express-after—
must use distinct paths and distinct inodes. Before/after bytes must match but
must not be the same file. Evidence directories are opened component-by-component
with descriptor-relative `O_NOFOLLOW`, then read twice from the pinned directory
descriptor, so replacing or symlinking an ancestor cannot redirect validation.
The evidence aggregate is SHA-256
over sorted records of `relative-path`, a NUL byte, the file SHA-256, and a
newline.

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
  --evidence-root ./evidence \
  --repo /absolute/path/to/clean/wiseacct_sso
```

The current implementation never exits `0` or emits
`PROVISIONAL_READY_FOR_REVIEW`, because controlled image collection is missing.
An otherwise complete seven-gate v2 group is `INCOMPLETE` solely with
`controlled-collector-required` and always keeps
`overallReplacementReady=false`. A future reviewed change may unlock the
provisional status only after a checked-in controlled collector exists and its
own pinned evidence is independently verified; manifest claims cannot unlock it.

Exit `1` emits a sanitized `status=INCOMPLETE` result for an otherwise valid
group that has missing/non-passing gates, false assertions, failed cleanup or
Express invariance, or mixed provenance. Exit `2` refuses malformed, unsafe, or
hash-mismatched input. Legacy schema-version `1` manifests are accepted only as
migration input and always return `INCOMPLETE` with
`migration-required:schemaVersion-1`; their evidence and manifest provenance
are never aggregated. The currently recorded independent and shared-state runs
therefore cannot form a group or be promoted by rewriting their old claims.

## Security evidence gate

The [toolchain freeze decision](security/TOOLCHAIN_FREEZE_DECISION.md) records
candidate routes, missing digest/signature evidence and activation prerequisites
for all 11 subjects. It does not freeze the active lock or authorize collection.

### Local execution-boundary admission

`security/execution_boundary.py` provides a local admission lease for future
controlled execution. It does not start or connect to a daemon, invoke a verifier,
resolve registry artifacts, verify signatures, or enable the online stager.
The existing controller still refuses a `FROZEN` lock in both modes.

`admit_boundary(root, verifier_sha256=..., trust_root_sha256=...)` requires an
absolute private directory with mode `0700`, a direct `daemon.sock` Unix socket
with mode `0600`, `verifier.bin` with mode `0500`, and `trust-root.json` with mode
`0400`. Hash arguments must come from independently reviewed policy, never from
the untrusted material being admitted. Synthetic test hashes are not real pins.
The verifier and trust-root bytes are opaque to this module.

The lease retains file descriptors, refuses symlink traversal, checks ownership,
file type, link count, exact permissions, bounded hashes and stable metadata, and
revalidates pathname bindings. `revalidate()` detects replacement or mutation;
the context manager closes retained descriptors on exit. Descriptions remain
`UNVERIFIED` and supply no execution command or authorization.

Socket metadata cannot prove the daemon process identity, namespace isolation or
network policy. Matching file hashes cannot prove publisher authenticity or
signature correctness. Revalidation also cannot make a subsequent path-based
execution/connect atomic. A future controller must establish those properties,
use the pinned resources safely at the actual operation boundary, and bind its
verification results to the source and artifact subjects before collection is
enabled. Retained descriptors pin inode identity, not immutable contents: a
same-UID process can write after revalidation. Before execution or trust-root
consumption, rehash and use an immutable snapshot (for example, a sealed memory
file) rather than trusting the earlier metadata check. This module is not yet
wired into the check-only controller.

### Online stager / offline intake contract

`ops/phase7/run-security-online-stager.sh check RUN_ID linux/amd64
ABSOLUTE_PRIVATE_OUTPUT_PARENT` is the check-only controller preflight. The same
interface accepts `linux/arm64/v8`. It binds a clean HEAD through the hardened
repository snapshot, validates the exact checked-in toolchain lock, and publishes
only controller-authored `INCOMPLETE` evidence into an existing caller-owned mode
`0700` output parent. Publication stays bound to an opened output-directory
descriptor across creation, writes, and no-replace rename. `collect` is reserved
but follows the same hardened clean-HEAD snapshot before the `UNFROZEN` refusal;
it does not invoke Docker, a scanner, or a network client. The wrapper clears
inherited environment variables and uses Python isolated mode.

The exact lock shape is documented by
`security/controlled-toolchain-lock.schema.json`. It separately pins builder,
collector, and six scanner repositories, versions, index/platform/config digests;
three Trivy artifact manifests and payloads; per-image and per-artifact signature
issuer/subject/Rekor policies; exact pip/npm HTTPS:443 origins; the complete staging
destination allowlist; and the fixed bootstrap binary path/hash. Downstream
collection networking remains `disabled`; only the future stager boundary is
`default-deny`. All checked-in candidate fields deliberately remain null, so no
digest or signing identity has been invented. A frozen test fixture produces only
declarative digest-bound staging subjects. It cannot produce an executable Docker
command until a private-daemon socket contract exists.

`ops/phase7/run-security-stager-intake.sh ABSOLUTE_PRIVATE_STAGER_INPUT_DIR RUN_ID`
is a schema-only offline intake boundary for artifacts that a separate, restricted
online stager may eventually collect. It never starts Docker, scanners, or network
clients. The private input directory must be owned by the caller, mode `0700`, and
contain only a mode-`0600`, single-link `online-stager-manifest.json` plus its
exactly referenced artifacts. The manifest contract is pinned in
`security/online-stager-manifest.schema.json`.

The manifest can assert only `STAGED_UNVERIFIED`. It binds the current clean HEAD
and Git tree through the same hardened repository snapshot implementation as the
security gate, as well as the checked-in toolchain-lock hash. Artifact validation
is admissible only after that lock is `FROZEN`; the checked-in `UNFROZEN` state
therefore remains incomplete without claiming intake validation. A future frozen flow admits
only Linux amd64/arm64 image bundles with unique builder, collector, and six
scanner-image roles; subject-bound signatures and attestations; fresh Trivy database
artifacts; request-bound pip/npm advisory responses; and an evidenced default-deny
network scope whose declared destinations are HTTPS port 443 only. Once the lock is
`FROZEN`, image, Trivy payload, advisory-origin, destination, and signature-policy
declarations must project exactly from it; a caller cannot substitute another pinned
subject. Signature descriptors bind the asserted issuer, identity, Rekor-inclusion
flag, raw evidence hash, and digest, but do not prove cryptographic authenticity.
That verification remains a future controlled-collector responsibility. Every referenced
file is descriptor-read, ownership/mode/link checked, and verified against its size,
SHA-256, and the bundle aggregate.

Image archives, Trivy payloads, signature and attestation material, network
observations, and advisory request/response bodies remain opaque raw artifacts; the
intake never parses archives or executes them. Separate exact `UNVERIFIED`
descriptors bind their raw hashes to image role/repository/digests/platform, Trivy
kind/update window, advisory lock/origin/request-response chain, or network
destination set as applicable. Every image and Trivy registry host must also appear
in the default-deny HTTPS:443 destination list. These bindings detect swaps without
mistaking self-asserted metadata for cryptographic verification.

A structurally valid bundle under the checked-in `UNFROZEN` lock exits `3` as
`INCOMPLETE` with `intakeValidated=false` and `MISSING_EVIDENCE`. Under a future
exactly projected `FROZEN` lock, it still exits `3` with
`CONTROLLED_COLLECTOR_REQUIRED`; only then may `intakeValidated=true`. Caller bytes
are never republished, and this intake can never emit `PASS`, `VERIFIED`, or
replacement approval. Missing input is
incomplete; unsafe, stale, expired, malformed, unbound, or unexpected input fails.
The wrapper clears its environment and uses fixed `/usr/bin` tools plus Python
isolated mode. This contract does not invent candidate image or scanner digests.

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
`candidate-inventory.json`, plus `collector-contract.json`,
`qualification-provenance.json`, `collector-attestation.json`, and
`image-metadata.json`. A caller-supplied toolchain lock or any other extra file
is rejected. Files must be single-link and owned by the caller;
the controller checks stable inode, size, owner, link count, mtime, and ctime
while copying them through descriptors into a private snapshot before parsing.

The checked-in `security/controlled-toolchain-lock.json` is exact and deliberately
`UNFROZEN`. Collection networking is fixed to disabled and the daemon policy to
isolated-disposable, but all builder/collector/scanner, Trivy artifact, signature,
advisory-origin, allowlist, and bootstrap pins remain null or empty rather than
being invented. The external `collector-contract.json` follows
`security/controlled-collector-contract.schema.json`, accepts only
`status=UNVERIFIED`, and binds the checked-in lock hash, the legacy report
aggregate, the complete non-contract bundle aggregate, and all three companion
attachment hashes.

The qualification provenance is the Phase 7 version-2 security record. Its
revision, Git tree, Express/FastAPI application aggregates, schema, lock, and
configuration aggregates are recomputed from the current clean repository.
The controller binds explicit Git-directory and work-tree descriptors to the
canonical standalone or linked-worktree metadata, disables replacement and
lazy object retrieval, and rejects config includes, `core.worktree`, partial
clones, promisors, configured alternates, and object-alternates files. Clean
status is therefore evaluated against the named real worktree. Pinned runner,
policy, rules, lockfiles, Dockerfile, and toolchain-lock bytes—as well as every
repository aggregate—come from immutable HEAD blobs, not caller-mutated
worktree files.
The attestation hash and Express/FastAPI image IDs must match the unverified
collector attestation. Image metadata separately binds the FastAPI image ID,
config digest, base-image digest, legacy security provenance hash, qualification
provenance hash, attestation hash, and repository lock hash. `VERIFIED` or
`PASS` claims in any external control record fail rather than unlocking the
gate. The wrapper uses absolute `dirname`, clears its environment, fixes PATH,
and invokes `/usr/bin/python3 -I`, so ambient shell/Python startup variables
cannot select the controller or execute startup code.

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
bundle at `INCOMPLETE` with both `TOOLCHAIN_LOCK_UNFROZEN` and
`CONTROLLED_COLLECTOR_REQUIRED`: opaque caller-authored
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

## Synthetic backup/restore evidence gate

`ops/phase7/run-backup-restore-gate.sh ABSOLUTE_SANITIZED_INPUT_DIR RUN_ID`
is a read-only controller for evidence from a future controlled disposable
collector. It does not invoke PostgreSQL tools, start services, use Docker,
connect to a database, or perform a backup. The private mode-0700 input
directory must contain exactly three owned, single-link, mode-0600 regular files:
`backup-restore-evidence.json`, `provenance.json`, and
`collector-attestation.json`. The controller snapshots them through stable
descriptors and rejects symlinks, hardlinks, unsafe modes, directory changes,
oversize input, unexpected files, and read races.
The wrapper resolves `dirname` by absolute path, clears the environment, supplies
only a fixed system `PATH`, and invokes `/usr/bin/python3 -I`; ambient `PATH`,
`PYTHONPATH`, `PYTHONHOME`, `ENV`, and `BASH_ENV` cannot select commands or load
Python/shell startup code. Database identifiers are ASCII, contain `_test_`,
and are limited to PostgreSQL's 63-byte identifier boundary before distinctness
is evaluated.

The exact contract and explicitly unfrozen policy are
`backup_restore/backup-restore-evidence.schema.json` and
`backup_restore/backup-restore-policy.json`. Evidence must identify versioned
`pg_dump` and `pg_restore` executables, two distinct `_test_` database names
with version-2 synthetic-only provenance, and an encrypted PostgreSQL custom
artifact. Encryption is exactly `AES-256-GCM`; the fixed local-runner key owner
and run-bound ephemeral URN are required, never a raw key or URL. The ciphertext
hash must differ from the plaintext dump hash, while the decrypted restore-input
hash must equal that dump hash. Sizes, deletion hash, accessors,
expiry, and deletion confirmation must reconcile. Plaintext publication,
retention, or discovery is a policy failure.

Schema/catalog and core-auth-state digests must match before and after restore.
Every Prisma auth table must appear exactly once with matching row count and
content digest. The FastAPI smoke is an exact read-only synthetic check set
against the restore database with zero mutations. Structured Express identity,
image, state, restart count, and start time must be identical before and after.
Cleanup requires both disposable databases dropped, encrypted artifact and
private temporary material removed, deletion confirmed, and an empty candidate
inventory. Start/end timestamps and derived durations are mandatory. The policy
records `status=UNFROZEN`, a 67108864-byte plaintext maximum, null artifact
retention/RPO/RTO thresholds, `synthetic-only` source scope, and
`ephemeral-not-backed-up` Redis disposition. No operational threshold is
invented by this gate.

Exact Phase 7 provenance-v2 and unverified collector-attestation attachments
bind the current gate/run, disposable topology, Express and FastAPI image IDs,
collector identity, and the SHA-256 of the complete attestation. Missing
attachments are incomplete; mismatched identities, hashes, or images fail.
The checked-in `backup-restore-fixture-manifest.json` freezes one canonical
identity projection for each User, password credential, role, and refresh-token
session sentinel. Each manifest digest is recomputed from canonical
`{table,recordId}` JSON. Evidence binds the manifest hash and proves the exact
non-zero source/restore count and digest for all four sentinels; empty databases
cannot satisfy the gate.

Missing evidence publishes `INCOMPLETE`; unsafe, malformed, inconsistent, or
policy-violating evidence publishes `FAIL`. Even a fully valid external bundle
publishes `INCOMPLETE` with `POLICY_UNFROZEN` and
`CONTROLLED_COLLECTOR_REQUIRED`, because a caller
cannot authenticate its own execution. Only controller-generated
`result.status` and `gate-result.json` are atomically published without
replacement under `evidence/phase7-backup-restore/<run-id>/`; caller bytes are
never republished. The result always records `gateId=backup-restore` and
`overallReplacementReady=false`.
