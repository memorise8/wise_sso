# FastAPI SSO migration session handoff

Status captured: 2026-09-06 (Asia/Seoul)

## Read this first

### 2026-09-09 Naver/Kakao development continuation

The common OAuth harness now supports `oauth-naver` and `oauth-kakao` through
`--oauth-launch-config <private-json>`, with explicit provider binding across
launch policy, disposable fixture, owned provider-record pipe and flow assertions.
The existing Google CLI remains compatible. Naver/Kakao local HTTP doubles and
owned Python child probes cover both runtime role orderings; these are not actual
Express/FastAPI engine runs or live PostgreSQL/Redis qualification.
See `contracts/evidence/oauth-provider-flows-development.md` for final validation
and independent review evidence. A06/A07 are development-prepared, not closed;
all provider results retain `qualifying=false` and the explicit
`provider-error-state-lifecycle` gap. Overall status remains **NOT_READY**.
Final independent reviews: code APPROVE + architecture CLEAR. Checkpoint contracts
263 passed / 244 subtests (separate in-progress A08 test excluded); FastAPI
1416 passed / 79 skipped; changed-file Ruff/format/strict mypy passed.

Next coding work remains the independent per-runtime OAuth corpus, remaining
approved core-flow coverage and authenticated collector/orchestrator integration.
Actual engine/store qualification requires the designated disposable D1 runner;
do not use the production Docker daemon. Existing DB reuse and Prisma ownership
remain unchanged. No operating Express source or `.omc/` was modified.

### 2026-09-09 W0/W1 continuation (supersedes the historical Google status below)

Execution follows `.omx/plans/python-first-ready-2026-09-09.md` using native
subagents. Existing production DB/Redis and Prisma ownership remain unchanged.
The Google mixed-only flow is connected to the common CLI through
`--flow oauth-google --oauth-google-launch-config <private-json>`; it is not an
independent Google corpus or authenticated qualification.
See `contracts/evidence/python-ready-baseline.md` for fresh baseline/environment
checks and `contracts/evidence/google-flow-dispatch-development.md` for dispatch.

Review repairs include actual Google identity residual counts, preflight before
mutation/runtime creation, explicit health ports, drain-before-reset, and pre-spawn
offline bootstrap/configuration checks. A05 remains open: both application runtimes
currently handle provider errors before consuming OAuth state. The harness now
reports `unverified: ["provider-error-state-lifecycle"]` instead of blessing reuse
of that state. A coordinated oracle/application hardening decision and regression
are needed; no operating Express source was changed to hide this gap.

Fresh FastAPI baseline: 1416 passed, 79 skipped; Ruff/format/mypy passed. This is not
new live PostgreSQL/Redis qualification. The guarded Compose configuration passes
check-only and candidate resources are EMPTY, but user/net namespace probes fail
with permission errors and the default Docker daemon hosts production containers.
The `.venv/bin/uvicorn` executable is present. No missing-uvicorn claim should block
resumption. Obtain a designated disposable runner/CI before actual Google engines;
do not substitute this shared daemon for formal D1 isolation.

Before resuming, inspect the current diff and latest independent review results.
Final W1 development review: code APPROVE + architecture CLEAR; frozen contracts
236 passed / 202 subtests, Ruff/format/strict mypy on 11 code/test files PASS.
Code/test/manifest/profile hashes stayed unchanged throughout that regression.
Next acceptance is actual isolated independent runtime comparison, then owned
Google E→F/F→E execution. W3a trust, W4/W5 collectors/orchestration, W6 canonical
qualification and W7 operator cutover remain unfinished. Do not mark READY or
discard original work based on this development checkpoint.

Active continuation after `ac2d1fe`: the user reaffirmed that the stopping target is
the reviewed READY_FOR_APPROVAL plan, not an intermediate development checkpoint.
Mail A01b/A02/A03 development integration is committed as `69a948d` with independent
code APPROVE + architecture CLEAR. Real-engine/live-store qualification is still open.
A05 Google flow and its new owned launcher/fixture adapter remain in progress.
A04 test-only provider transport is committed as `ac605cd`; its private invocation
pipe continuation is `d9a6eb4` (code APPROVE + architecture CLEAR). This closes the
transport-channel WATCH but not downstream Google launcher/flow integration.
B02 dormant blob verifier consumer is committed as `fb24115` (code APPROVE,
architecture CLEAR for the dormant slice, not authenticated activation).
See the provider-transport and verifier-consumer development evidence documents.
C01a is committed
as `d13de9d`, and R04 dormant backfill/merge as `20e649e` after scoped code review
approval (45 combined ops/database/no-DDL tests). Google changes remain
uncommitted and need integration/review. The current
working tree must be inspected before resuming, not reset to the historical counts below.
C02/C03 development scaffold is also committed as `72872b5`, with code APPROVE and
architecture WATCH (combined COMMENT): see
[`performance-collector-development.md`](contracts/evidence/performance-collector-development.md).
Actual flow actions, owned backend cleanup, authentication and 20k-times-three runs
are absent; this commit does not complete either parent task.
Latest leader FastAPI regression: `1416 passed, 79 skipped`, one existing Starlette
deprecation warning; Ruff passed, format checked 156 files, strict mypy passed
111 configured source/test files and a separate 70-file src/ops check. Mail exact
pre-teardown state and malformed-input fixes are implemented. Full-phase cleanup
fixes (startup, process, consumed pidfd, capture and session) passed independent
code APPROVE and architecture CLEAR. Leader mail/assets tests: 59 passed/120 subtests.
A04's new private invocation pipe also has code APPROVE + architecture CLEAR,
and 14 leader-run tests/11 subtests. A05 is
implementing the actual owned-process/pipe consumer after closing issuer/state/
cleanup defects; its canonical integration and final review remain open.
These are development regression results while work continues, not final gate evidence.
All parents and replacement remain NOT_READY. No production/Prisma ownership transfer,
Express source modification, active lock freeze or performance-policy selection occurred.
Continue safe local tasks; missing external inputs block only their dependent live steps.

Native-subagent continuation (2026-09-06): execution now follows the approved
six-group/25-task decomposition in `.omx/plans/ready-packages/README.md`, with
current progress in `.omx/plans/ready-packages/execution.md`. New development
checkpoints cover private loopback SMTP capture (A01a), same-process-group owned
runtime lifecycle (B01a), synthetic backup/restore invocation (R01a), and the
unauthenticated v2 statement interface (G01a). Parent A01/B01/R01/G01 tasks are
still incomplete; R04 has an inventory, not ownership-transfer evidence.
Do not repeat these checkpoints instead of completing their consumers.
The next functional work is A01b controlled private-mail fixture/launcher integration,
then A02 verification/attach and A03 reset/revoke. Existing `dev` guards are unchanged:
the SMTP transport must not be falsely labeled `CONTRACT_SERVER_MAIL_MODE=dev`.
Actual isolation, authenticated signing and all seven live gates remain unverified.
Final checkpoint commands/reviews are in
[`ready-package-foundations-development.md`](contracts/evidence/ready-package-foundations-development.md):
FastAPI `1317 passed, 79 skipped`; contracts `126 passed, 149 subtests passed`;
Ruff/format/strict mypy passed. Independent code and architecture reviews approve
only these four development checkpoints. Express/source guards/active lock unchanged.

Prior implementation checkpoint (2026-09-06): the approved READY plan's first M1
password direct-login/handoff HTTP driver is implemented under `contracts/bin/flow_driver.py`.
See [`password-flow-driver-development.md`](contracts/evidence/password-flow-driver-development.md)
for its exact tests, review and limitations, and `contracts/README.md` for CLI inputs.
It does not complete the remaining eight flows, live DB/Redis runs, full samples or
authenticated qualification. Replacement remains **NOT_READY**; Express is unchanged.
Continue from the local approved `.omx/plans/fastapi-replacement-ready.md` and execution
checkpoint rather than repeating the already completed admission/sealed-material work.

READY-path continuation (2026-09-06): see
[`READINESS_BLOCKERS.md`](fastapi-auth-server/ops/phase7/READINESS_BLOCKERS.md)
for the full seven-gate inventory and execution-environment observations.
The performance profile already fixes p95 at 120% of Express; recovery thresholds
and the approved plan's protocol-required p50 cutoff remain unselected. Current unprivileged `unshare` and `bwrap`
isolation probes both failed with permission errors. Installed `gh` 2.45.0 lacks
attestation verification and no `cosign` executable is on PATH. No host setting,
production Docker endpoint, or signing/registry configuration was changed.

The local admission lease now has `snapshot_material()`: verifier/trust-root
bytes are copied to sealed memory files and checked against reviewed hash inputs.
Copies are immutable after sealing and descriptors close on failure/context exit.
This closes the prior same-UID content-mutation gap for snapshot consumers, but
does not authenticate a publisher or implement verifier/daemon execution.
Project signing/registry configuration, an isolation-capable disposable runner,
and recovery policy inputs remain needed for live qualification. No gate or lock
has been promoted.
Independent security review approved the sealed-material slice after closing
append-before-seal and borrowed-descriptor reuse defects. Final regression:
`1021 passed, 79 skipped` in the FastAPI suite; separate contract suite:
`91 passed, 125 subtests passed`. Ruff lint/format and strict mypy for the four
security modules and two boundary test modules passed. These results do not
replace the seven live qualification gates. The Linux kernel sealing tests are
local byte-integrity evidence, not cryptographic verification or daemon isolation.

Execution-boundary continuation (2026-09-06):
`fastapi-auth-server/ops/phase7/security/execution_boundary.py` now implements
local admission of a private Unix socket and descriptor-pinned verifier/trust-root
files with reviewed hash inputs. It rejects unsafe permissions, links, mutations
and replacements, and closes its descriptors on context exit or admission failure.
It does not start/connect to Docker or perform cryptographic verification and is
not wired into the online stager. The active lock remains unchanged; both stager
modes still reject a synthetic complete `FROZEN` lock. Treat this as execution
infrastructure only, not a completed daemon/verifier or qualification result.
Next: establish authenticated verifier/trust-root inputs and implement the
isolated daemon lifecycle and verifier invocation under a reviewed network
boundary. Path revalidation alone is not atomic execution or daemon identity
proof. The existing freeze decision's identity and provenance blockers still apply.
Independent read-only review approved this admission-only slice. Its follow-up
requirement is to bind future execution/trust-root consumption to rehashed
immutable snapshots; retained descriptors do not stop same-UID content mutation.
Regression validation for this slice: `995 passed, 79 skipped` (45 added cases),
Ruff lint/format passed, and strict mypy passed for four security modules plus
the new boundary tests. The existing Starlette warning remains; skipped live
tests are not new qualification evidence.

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
