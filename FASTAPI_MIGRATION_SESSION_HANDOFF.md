# FastAPI SSO migration session handoff

Status captured: 2026-09-06 (Asia/Seoul)

## Read this first

Continuation update (2026-09-06): the next decision record is now
[`TOOLCHAIN_FREEZE_DECISION.md`](fastapi-auth-server/ops/phase7/security/TOOLCHAIN_FREEZE_DECISION.md).
It records all 11 candidate routes and unknown pins, with activation still blocked.
Follow its review status and prerequisites before the historical sequence below.
No active lock or runtime behavior changed. The next safe implementation slice is
the private-daemon/verifier contract with check-only execution retained; real
collection still depends on independently verified artifacts and signing identity.
Local validation for this documentation slice: `950 passed, 79 skipped`, Ruff
lint/format checks passed, and strict mypy passed for the three security
controllers. The existing Starlette deprecation warning remains. These checks
are regression evidence, not new live Phase 7 qualification evidence.

The Express server remains the production implementation. The FastAPI migration is
being developed and qualified in a separate provisional Git worktree. Do not route
production traffic to FastAPI and do not modify production database, Redis, secrets,
containers, credentials, or ingress from this worktree.

The FastAPI implementation is functionally complete through provisional Phase 6.
Phase 7 replacement qualification is in progress. The current replacement verdict is
`NOT_READY` because controlled security collection, performance, recovery/chaos,
rollback, same-SHA aggregation, and canonical refreeze/replay are not complete.

## Exact repository state

- Express/primary worktree: `/home/ruci/repo/wiseacct_sso`
- Express branch: `main`
- Express/main SHA at handoff: `54e182879c20c6d3922041b422ceb471da57d293`
- FastAPI provisional worktree: `/home/ruci/repo/wiseacct_sso_fastapi_provisional`
- FastAPI branch: `wip/fastapi-sso-pre-refreeze`
- Latest FastAPI implementation SHA before this handoff document:
  `f5281bc52ed16a9ad4902fedeada25676617e6c2`
- FastAPI implementation distance from `main` before this handoff commit: 30 commits
- Expected worktree state after the handoff commit: clean
- The primary worktree has a pre-existing untracked `.omc/` directory. Preserve it.

This is a provisional lane, not the future canonical migration branch. Do not rename
it to `feat/fastapi-sso-migration` or treat its base as `REFROZEN_BASE_SHA`.

## Start a new session here

Run these read-only checks before changing anything:

```sh
cd /home/ruci/repo/wiseacct_sso_fastapi_provisional
git status --short --branch
git rev-parse HEAD
git log -5 --oneline
```

The latest implementation commit immediately below the handoff commit should be
`f5281bc52ed16a9ad4902fedeada25676617e6c2`. If the history or worktree differs,
inspect the newer changes and update this handoff instead of resetting or discarding
them.

Use this prompt to resume:

```text
Continue the WiseAcct SSO FastAPI migration from
/home/ruci/repo/wiseacct_sso_fastapi_provisional.

Read FASTAPI_MIGRATION_SESSION_HANDOFF.md and
fastapi-auth-server/ops/phase7/README.md first. Preserve the Express production
runtime and all production DB/Redis/secrets/routing. Verify the current Git state
before editing. Continue Phase 7 from the security toolchain identity freeze review;
do not invent digests or signing identities and do not set the active lock to FROZEN
without authoritative evidence and independent review. Keep FastAPI NOT_READY until
all remaining gates are collected from the same source SHA. Implement, test, review,
and commit the next safe local slice autonomously.
```

## Completed implementation

### Phases 1-6

- Phase 1, `303b781`: FastAPI foundation, isolated configuration, lifecycle,
  structured logging, static assets, and guarded local Compose resources.
- Phase 2, `6b6e39d`: PostgreSQL/Redis persistence foundation, DML-only runtime role,
  Prisma-owned schema compatibility, concurrency primitives, and cleanup controls.
- Phase 3, `585e3e9`: public HTTP surface, readiness, JWKS/OIDC discovery, portal and
  dashboard assets, security headers, CORS, and Express-compatible error responses.
- Phase 4, `2139e1e`: registration, login, access/refresh JWTs, Argon2 interoperability,
  refresh rotation, logout, lockout, rate limiting, audit ordering, and black-box auth.
- Phase 5, `fc8d07d`: email verification, password reset, mail/provider boundaries,
  OAuth state/handoff, identity linking, and mixed Express/FastAPI writer races.
- Phase 6, `f94cd74`: admin/manage APIs, authorization, audit filtering/redaction,
  role/status/session mutation races, date compatibility, and runtime operations.

All of these results are synthetic and provisional. They do not authorize cutover.
Detailed evidence is under `fastapi-auth-server/evidence/phase1` through `phase6`.

### Phase 7 completed slices

- Independent differential qualification and disposable runtime launcher.
- Shared PostgreSQL/Redis mixed-runtime qualification.
- Qualification provenance v2 and same-source aggregation contracts.
- Image source/provenance guard.
- Fail-closed security evidence contract and policy validation.
- Performance evidence contract. This is a validator contract, not a live result.
- Backup/restore evidence contract. This is a validator contract, not a live restore.
- Controlled security toolchain lock schema, intentionally `UNFROZEN`.
- Online-stager offline intake with opaque artifact preservation and descriptor binding.
- Check-only online-stager controller with clean-HEAD binding and no external execution.

Most recent Phase 7 commits:

```text
f5281bc feat: add phase 7 security stager controller
a5acd82 feat: define phase 7 security staging intake
d7ac041 feat: bind phase 7 security toolchain
010098d feat: define phase 7 backup restore gate
9490dea feat: guard phase 7 image provenance
256ecf2 feat: bind phase 7 qualification provenance
0384fdc feat: define phase 7 performance contract
bbeb616 feat: add fail-closed phase 7 security gate
4f2873e feat: harden phase 7 qualification security
6ac03c3 test: record shared-state phase 7 evidence
```

## Verified evidence

Independent runtime evidence:

- Run: `20260901t105243_3598166`
- Runtime cleanup: PASS
- Express snapshot unchanged: true
- Candidate resources after cleanup: zero
- Qualification result: `INCOMPLETE_INDEPENDENT_PASS`
- Overall replacement ready: false

Shared-state runtime evidence:

- Run: `20260901t114832_3911115`
- Result count: 100
- Concurrent trials: 70
- Mixed-runtime overlap count: 70
- Overlap mismatches: 0
- Cleanup and integrity: PASS
- Express snapshot unchanged: true
- Full Phase 7 sample satisfied: false
- Overall replacement ready: false

The final test run before this handoff passed:

```text
950 passed, 79 skipped, 1 Starlette TestClient deprecation warning
```

The warning is non-blocking and unrelated to the migration behavior.

The committed online stager was also executed from clean HEAD in both modes:

```text
check   -> exit 3, status=INCOMPLETE, toolchainFrozen=false
collect -> exit 3, status=INCOMPLETE, toolchainFrozen=false
```

Both paths produced controller-authored evidence only. They performed no Docker,
scanner, registry, advisory-service, or external network operation.

## Current security boundary

The active file
`fastapi-auth-server/ops/phase7/security/controlled-toolchain-lock.json` is
`schemaVersion: 2` and `status: UNFROZEN`. Builder, collector, scanner, Trivy,
signature-policy, advisory-origin, allowlist, and bootstrap pins remain null or empty.
This is intentional. Do not fill them with remembered, tag-only, or inferred values.

The check-only controller already prevents:

- `check` or `collect` from bypassing a clean committed source snapshot;
- ambient Docker socket/`DOCKER_HOST` collection plans;
- executable collection commands before a controlled daemon contract exists;
- mutable `latest` references and malformed/null frozen locks;
- nested lock-object aliasing;
- output-parent and staging-entry symlink/inode substitution;
- signature-policy, platform, config, Trivy, advisory, or destination projection swaps;
- caller-provided `PASS`, `VERIFIED`, or replacement-ready publication.

The intake preserves raw OCI archives, signatures, attestations, network observations,
Trivy payloads, and advisory request/response bytes as opaque artifacts. Separate
`UNVERIFIED` descriptors bind their hashes. Structural binding is not cryptographic
verification.

## Why the lock is not frozen

The remaining pins require authoritative supply-chain evidence. Trivy had a 2026-03
release/distribution compromise, so tags and `latest` are insufficient. Require exact
index/platform/config digests plus signature and transparency-log evidence. See the
[Trivy advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
and [Sigstore verification guidance](https://docs.sigstore.dev/cosign/verifying/verify/).

Official, stable signer identity/provenance was not established for every Semgrep,
Gitleaks, and Trivy DB/check artifact during the last review. Leave those fields null
until verified. An acceptable alternative is to build project-controlled images from
reviewed source commits and sign them through a project-owned, documented identity.

Fresh `pip-audit` and `npm audit` results require a controlled online advisory stage;
they cannot be treated as newly generated offline PASS evidence. Their request,
response, origin, lock hash, and observation time must be captured and later verified.

## Next development sequence

### 1. Produce the toolchain freeze decision

Create a reviewed, non-secret decision document containing one row per builder,
collector, six scanners, and three Trivy artifacts:

- upstream versus project-built choice;
- source/release reference;
- repository and version;
- index digest;
- amd64/arm64 platform and config digests;
- expected issuer and signer identity;
- Rekor/bundle requirement;
- license and maintenance notes;
- authoritative evidence URL or command output hash;
- `FREEZE`, `REBUILD`, or `BLOCKED` verdict.

Unknown values stay null. Do not change the active lock in the same writer pass that
selects the values; use an independent reviewer first.

### 2. Freeze the lock only after review

Update the active lock to `FROZEN` only when every required field passes the schema,
runtime validator, signature-policy review, destination projection, and independent
verification. A partially populated frozen lock must fail.

### 3. Implement controlled online collection

The current controller is check-only. Actual collection still needs:

- an isolated disposable daemon with an explicit private socket;
- default-deny egress and exact HTTPS:443 allowlist/proxy evidence;
- digest-only pulls;
- independent Cosign/signature/attestation verification before image execution;
- no Docker socket inside collector/scanner containers;
- raw artifact and network observation capture;
- secret/PII sanitization and fail-closed cleanup;
- atomic private receipt publication consumed by the existing offline intake.

This controlled execution may require external network and signing/registry access.
Do not silently broaden local development authorization into production access.

### 4. Complete remaining Phase 7 gates

After controlled security evidence succeeds, run and validate:

1. performance evidence;
2. live disposable backup/restore;
3. chaos/failure scenarios;
4. local rollback;
5. full approved sample counts;
6. all seven gates aggregated from the exact same source SHA.

### 5. Canonical refreeze and replacement verdict

Only after Phase 7 is complete:

1. finish the original runtime prerequisite deployment/post-deploy validation;
2. record `REFROZEN_BASE_SHA`;
3. create the canonical FastAPI worktree/branch from that SHA;
4. cherry-pick reviewed FastAPI-only commits;
5. rerun Express regression, FastAPI tests, schema/security drift, shared-state,
   performance, recovery, rollback, and same-SHA aggregation;
6. then issue the replacement/cutover verdict.

## Commands for local verification

These commands are safe and do not start Docker or access external services:

```sh
cd /home/ruci/repo/wiseacct_sso_fastapi_provisional/fastapi-auth-server
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy --strict \
  ops/phase7/security/online_stager.py \
  ops/phase7/security/offline_stager_intake.py \
  ops/phase7/security/security_gate.py
```

Do not run production Compose files, production migrations, credential rotation,
canary routing, or external provider tests from the provisional worktree.

## Source-of-truth order

Use these sources in this order:

1. This handoff document for current session state and next steps.
2. `fastapi-auth-server/ops/phase7/README.md` for implemented gate contracts.
3. Checked-in schemas, validators, tests, and committed evidence.
4. `docs/model-evaluation/SSO_FASTAPI_MIGRATION_PRD.md` for product requirements.
5. `docs/model-evaluation/MULTI_MODEL_EXPERIMENT_PROTOCOL.md` for the model experiment.

The ignored local draft `.omx/plans/phase7-online-security-stager.md` describes an
earlier `a5acd82` plan and is partially superseded by `f5281bc`. Do not use it as the
current execution plan without reconciling it with this handoff and the committed code.

## Stop conditions

Stop and keep FastAPI `NOT_READY` when any of the following is true:

- a digest, signer identity, issuer, provenance, or advisory origin is unverified;
- any gate uses a different source SHA;
- production Express, DB, Redis, secret, or routing state would be changed;
- evidence can be replaced, caller-authored PASS can be published, or cleanup fails;
- the full approved sample, performance, security, recovery, chaos, or rollback gate
  is missing or incomplete.
