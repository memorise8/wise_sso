# Python migration restart baseline — 2026-09-09

Status: DEVELOPMENT_ONLY / NOT_READY. This is W0 evidence for
`.omx/plans/python-first-ready-2026-09-09.md`, not a qualification receipt.
Baseline HEAD: `2280aef`; the worktree contained seven untracked Google harness
files. Subsequent W1 edits are not part of a clean, frozen source qualification.
The existing application, Express production source, schema owner and operating
database were not changed by these checks.

## Fresh checks

Commands ran from the provisional worktree, except the FastAPI checks which ran
from `fastapi-auth-server/`. Existing locked dependencies were used offline.

| Command | Observed result |
|---|---|
| `uv run --offline --locked --project fastapi-auth-server pytest -q contracts/tests/test_google_oauth_fixture.py contracts/tests/test_oauth_google_flow.py contracts/tests/test_private_oauth_flow_launcher.py` | Initial seven-file baseline: 33 passed; one collection warning for the helper dataclass `TestRuntimeBinding` |
| `uv run --offline --locked pytest -q` | 1416 passed, 79 skipped, one upstream Starlette/httpx deprecation warning; 35.14 seconds |
| `uv run --offline --locked ruff check .` | PASS |
| `uv run --offline --locked ruff format --check .` | 156 files already formatted |
| `uv run --offline --locked mypy` | PASS, 111 configured source files |
| `fastapi-auth-server/ops/dev-compose.sh --check-only fastapi-auth-server/.env.example` | PASS; no resources created |
| `fastapi-auth-server/.venv/bin/python fastapi-auth-server/ops/phase7/runtime_candidate_state.py resources` | EMPTY |
| `test -x fastapi-auth-server/.venv/bin/uvicorn` | PASS; the existing executable is present |
| `unshare --user --map-root-user --net true` | FAIL: writing `/proc/self/uid_map` is not permitted |
| `bwrap --unshare-user --unshare-net --ro-bind / / true` | FAIL: configuring loopback is not permitted |

The 79 skips are not successful integration or qualification results. No real
database integration run was started in this baseline. Docker inventory was read
without retrieving container environments: the default daemon contains operating
Express/PostgreSQL/Redis containers. It is not an approved private D1 daemon.
No production HTTP request, database query, restart, routing or credential change
was performed by these checks.

## Existing real-runtime entrypoints and topology

- Independent: `fastapi-auth-server/ops/run-phase7-independent-integration.sh`.
  Requires a clean committed checkout, creates two disposable PostgreSQL databases
  and roles, uses candidate Redis DBs 13/14, and runs Express/FastAPI on separate
  loopback ports 4410/4411. `ops/phase7/runtime_material.py` builds synthetic runtime
  material. The runner owns teardown and records cleanup/Express identity checks.
- Shared: `fastapi-auth-server/ops/run-phase7-shared-integration.sh`.
  Uses one disposable PostgreSQL database and candidate Redis DB 13;
  `ops/phase7/runtime_shared_material.py` creates its runtime material. The existing
  corpus is not the final full-sample qualification.
- These are existing provisional guarded Compose paths, not formal controlled
  isolation. They were inspected, not executed. Do not run `up` or either runner
  against an arbitrary daemon merely because the configuration check passed.
- New Google path: `contracts/bin/private_oauth_flow_launcher.py --config
  <owned-mode-0600-json>`. It must own its two child processes and private provider
  pipe. Existing already-started servers cannot simply be passed to it.
  Actual Express startup needs the loopback wrapper and test provider preload;
  actual FastAPI startup needs the test-only provider factory. Config generation
  and real-engine orchestration remain to be connected and tested.
- `run_google_flow` currently tests only mixed Express/FastAPI orderings. It must
  not be inserted into an independent gate and reported as independent Google
  evidence. Independent coverage remains an explicit W1/W2 acceptance gap.

Historical real PostgreSQL/Redis and mixed-writer evidence in
`fastapi-auth-server/evidence/phase5/result.md` and `phase6/result.md` remains valid
as historical partial evidence; it was not overwritten or promoted to latest-SHA
qualification.

## W1 review repair

The first independent code finding identified a literal zero for residual Google
identity records in `google_oauth_fixture.py`. A regression proved that retained
`SocialAccount` rows could be reported clean. The residual probe now queries the
provider/subject count. Before the fix: both zero/one-row regression subcases
failed. After the fix: 9 fixture tests and 2 subtests passed. This uses a mocked SQL
backend and is not a claim that the new fixture ran against real PostgreSQL.

Further review repairs add mandatory preflight before fixture CLI operations and
an exact DB/Redis/schema preflight result before launcher creation; reject missing,
zero, invalid or non-loopback health ports before allocating the provider pipe;
and drain owned runtimes before fixture reset. A failed drain now prevents reset
instead of allowing cleanup to race a live writer. The two drain-order regression
tests failed before the change and passed afterwards. Their first failing run left
two owned synthetic probes alive because the regression itself lacked unconditional
cleanup: both were identified and terminated, and the test now registers cleanup
even when its assertion fails. An unrelated probe dating from September 6 was
preserved, not counted as a resource created by this run.

### Application/PRD gap: provider-error state lifecycle

Both `auth-server/src/controllers/oauth.controller.ts` and
`fastapi-auth-server/src/wiseacct_sso/api/routes/oauth.py` currently handle a provider
`error` before state consumption. The original Google harness reused that valid
state for a later successful callback. That is not proof of the PRD's full OAuth
single-use/replay requirement (§8.7, §11.1, §14).

The development harness now keeps its provider-error response probe separate from
the successful state lifecycle and reports only `oauthSuccessStateReplayRejected`.
It explicitly emits `unverified: ["provider-error-state-lifecycle"]`; A05 stays open.
The remaining acceptance scenario is a fresh start, a provider-error callback with
that valid state, then rejection of a callback reusing the same state. Coordinated
Express/FastAPI contract hardening requires a separate approved baseline change;
this work does not edit operating Express or silently waive the PRD requirement.

## Final W1 development verification

- Frozen full contracts: `uv run --offline --locked --project fastapi-auth-server
  pytest -q contracts/tests` → **236 passed, 202 subtests passed**, 72.11 seconds.
  All 11 changed/new code/test files plus manifest/profile had identical SHA-256
  values before and after this run. Earlier runs during edits are superseded.
- All 11 code/test files: Ruff check/format and strict mypy PASS.
- Final post-integration FastAPI regression: `uv run --offline --locked pytest -q`
  from `fastapi-auth-server/` → **1416 passed, 79 skipped**, 35.02 seconds; one
  unchanged upstream Starlette/httpx deprecation warning.
- Independent `w1_google_code_review`: APPROVE for the bounded development
  checkpoint; `w1_google_arch_review`: CLEAR, reaffirmed after the final guard and
  exception-cause fixes. Neither closes A05 or READY.
- Final policy requires full FastAPI/Prisma fixture preflight even when Express is
  the producer; fixture interpreter/loader overrides are rejected. Interrupt
  regressions prove the original KeyboardInterrupt/SystemExit object survives and
  the concrete cleanup failure remains chained as its cause.
- Final candidate resources: EMPTY. The pre-existing September 6 probe is preserved;
  no newly created Google probe remains. Primary Express worktree still has only
  its pre-existing untracked `.omc/` and no tracked changes.
- Manifest SHA-256:
  `40856502f445dd0a01033c98e40d70dcb948779460fe9e4948ec8566b4e2edde`.
  Profile-v1 changes only this binding, not thresholds or sample sizes.

## Pending inputs and next action (unchanged)

- D1: designate an isolated disposable runner/VM or CI and its non-secret access
  configuration; current user/network namespace attempts failed as recorded above.
- D2/D3: independently authenticated verifier/bootstrap and approved registry/signing
  identity are still absent from the active `UNFROZEN` lock. No values were guessed.
- Continue W1 common dispatch, independent code/architecture review and targeted
  regressions locally; then record exact real-engine config/bootstrap commands in
  the designated environment. Preserve W2–W7 and policy/canonical/staging inputs as
  unfinished until their actual evidence exists.
