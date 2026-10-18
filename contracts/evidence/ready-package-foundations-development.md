# READY package foundations — development evidence only

Date: 2026-09-06. Started from clean `606581a`. Native implementation agents owned
A01a, B01a and R01a; leader owned G01a and integration. A read-only agent mapped R04.
Independent code reviewers and a distinct architect reviewed the final checkpoints.
No production source/runtime, DB, Redis, routing, secrets or `.omc` was changed.
No dependency was added, policy frozen, signer invented or qualifying gate enabled.

## What is implemented

| Checkpoint | Implemented and tested | Parent work still required |
|---|---|---|
| A01a | Private loopback STARTTLS capture with actual Express `createMailService` and FastAPI `SmtpMailService`; bounded token spool, scope/TTL, inode protection, startup/close rollback and retryable cleanup | A01b controlled fixture/launcher integration, then A02/A03 HTTP/state flows |
| B01a | Actual owned child daemon, pinned executable FD, PID/start-time/pidfd/socket-peer checks, bounded same-PG termination, FD-bound root cleanup and interruption-safe ownership | Approved isolated backend, network default-deny, escaped-descendant containment, B02 consumer and D1 |
| R01a | Backend invocation path for custom pg_dump, ephemeral AES-256-GCM, pg_restore, 11-table/schema/4-sentinel comparison and observed cleanup | Actual PostgreSQL run, exact tracked migration input, FastAPI smoke, Express invariance, gate consumer, D1/D4 |
| G01a | Exact 24-field byte-preserving statement/schema; topology and input/output bindings, versioned acyclic pre-sign inventories; detached byte-digest checks | B02/B03 cryptographic authentication and seven-producer/consumer migration |
| R04 inventory | All 14 existing maintenance job IDs mapped in `ops-successor-development-inventory.md` | Reviewed successor decisions, disposable integration and actual single-owner/scheduler evidence |

**None of A01/B01/R01/G01/R04 is complete.** Each completed sub-checkpoint is
development-only. G01a parsing cannot authenticate signatures. B01a explicitly
allows observation, not isolation, of current namespaces. R01a was tested with a
fake PostgreSQL backend and real bounded subprocesses, not an actual database.
R01's successful CLI exercise still exits 3 and sets `qualificationEvidence=false`.
Existing qualification entrypoints, finalizer, manifest/profile binding and active
toolchain lock remain unchanged. Replacement verdict remains **NOT_READY**.

## Final verification

From `fastapi-auth-server/`:

```sh
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked mypy --strict \
  ops/phase7/collector_attestation.py ops/phase7/collector_runtime.py \
  ops/phase7/backup_restore_collector.py \
  tests/static/test_collector_attestation_protocol.py \
  tests/static/test_phase7_collector_runtime.py tests/unit/test_backup_restore_collector.py
```

Results: **1317 passed, 79 skipped**, one existing Starlette deprecation warning;
Ruff passed; all 148 Python files formatted; configured mypy 105 files passed;
explicit new ops/tests mypy 6 files passed. Skipped integration tests are not live evidence.

From repo root:

```sh
uv run --locked --project fastapi-auth-server pytest -q contracts/tests
uv run --locked --project fastapi-auth-server ruff check \
  contracts/bin/private_mail_capture.py contracts/tests/test_private_mail_capture.py
uv run --locked --project fastapi-auth-server ruff format --check \
  contracts/bin/private_mail_capture.py contracts/tests/test_private_mail_capture.py
uv run --locked --project fastapi-auth-server mypy --strict \
  contracts/bin/private_mail_capture.py contracts/tests/test_private_mail_capture.py
git diff --check
```

Results: **126 passed, 149 subtests passed**; lint/format/strict mypy passed.
Additional independent targets: A01a19 tests/3 subtests, three runs with resource
and unraisable warnings promoted to errors; B01a33 tests; R01a22 tests/61 with the
existing backup gate; G01a241 tests. The backup subprocess terminal-state regression
was repeated ten times after fixing a legitimate Linux X/Z timing variation.

## Independent review and retained limits

- `mail_backup_checkpoint_review`: final APPROVE for A01a/R01a.
- `runtime_checkpoint_review`: final APPROVE for B01a/G01a.
- `g01_protocol_review` (architect): final APPROVE/CLEAR for all four bounded checkpoints.
- No remaining severity finding for these checkpoint scopes; this is not READY approval.

Review fixes covered startup interruptions, retryable cleanup, socket handoff races,
root replacement, unreaped leader/PGID lifetime, single-owner FD handoff, ambiguous
DB creation and failed cleanup probes. Same-UID hostile descendants escaping the
original group remain outside B01a containment; no collector should claim otherwise.
R01's mutable local migration discovery cannot be promoted into exact-SHA qualification.

## Resume

Approved parent/decomposition plans remain in ignored `.omx/plans/`; preserve them
with this worktree. Current local ledger is `.omx/plans/ready-packages/execution.md`.
Next functional step: **A01b controlled private-loopback mail launcher/fixture
integration → A02 verification/attach → A03 reset/revoke**. Do not relabel SMTP as
`CONTRACT_SERVER_MAIL_MODE=dev`, weaken the current guard, or redo the initial login flows.
Missing D1–D7 values block their dependent live steps, not independent safe code work.
Actual READY requires remaining functional implementations and authenticated same-SHA
seven-gate/canonical/staging evidence; production cutover and Express retirement remain separate.
