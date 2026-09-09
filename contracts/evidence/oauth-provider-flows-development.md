# Naver/Kakao mixed-flow extension — development only

Date: 2026-09-09 (Asia/Seoul). Extends the Google checkpoint `a22f709`.

## Implemented boundary

The common flow CLI selects exactly one `oauth-google`, `oauth-naver` or
`oauth-kakao` development flow. Naver/Kakao use `--oauth-launch-config`; the
legacy Google option remains supported. Conflicting configuration options and
cross-provider results fail before they can produce a passing output.

The shared flow specification binds authorize origin/path, scope, synthetic
client/code, fixture name and snapshot names to the selected provider. Launch
policy binds that provider to the fixture environment, exact runtime allowlist,
single transport scenario, credentials and callback. Fixture provider/subject/ID
validation precedes mutation; identity snapshots observe the database and residual
queries count the selected provider/subject. The owned record pipe is consumed
in-process, and runtime draining still precedes fixture reset.
The identity assertion proves that selected link, not absence of all unrelated
cross-provider identities; broader write-isolation evidence remains outside this
checkpoint.

Tests cover both role orderings, provider-specific authorization/state/record
checks, wrong-provider fixtures/records/scopes, configuration mismatch and the
actual private pipe between owned Python probe subprocesses. HTTP app doubles
and those Python probes are not real Express/FastAPI engine qualification.

The historical Google module/adapter filenames remain deliberately compatible;
this change reuses one implementation rather than duplicating provider runners.
The manifest adds a separate nonqualifying mixed-only binding. Only the manifest
hash changes in the performance profile; flow order, sample counts and thresholds
are unchanged. The independent four-flow corpus is not expanded or relabeled.

## Validation

Final frozen leader regression: `263 passed, 244 subtests passed` (78.64 seconds).
This runs all checkpoint contract tests, explicitly excluding the concurrently
authored, separate A08 `test_refresh_race_flow.py` file.
SHA-256 values for all 10 changed Python files and the manifest/profile were
unchanged across that run. FastAPI regression: `1416 passed, 79 skipped`
(35.22 seconds), with one existing Starlette/httpx deprecation warning.
Changed-file Ruff check, format check and strict mypy passed; FastAPI-wide
Ruff/format and mypy also passed (156 formatted files, 111 typed source files).

Independent review initially found policy-valid scenarios that disagreed with
the flow's fixed public client/code. Policy now rejects that mismatch before
runtime validation, and an independent cross-layer regression guards drift.
Stale manifest gap wording was corrected and its profile hash rebound.
Final code review: **APPROVE**; final architecture review: **CLEAR**. Both are
limited to this development checkpoint, not A05/A06/A07 or READY approval.

## Remaining acceptance work

All provider outputs remain `qualifying=false`, with
`unverified=["provider-error-state-lifecycle"]`. A05/A06/A07 and the whole
migration remain open / **NOT_READY**. The provider-error state lifecycle requires
an explicit application/oracle contract repair, not a relaxed harness assertion.
Independent per-runtime provider trials, real disposable engines/stores, approved
samples and authenticated collection are still required. Remaining driver work
also includes refresh race, admin and limiter coverage under the existing plan.

Production Express, existing DB/Redis, Prisma ownership and `.omc/` are unchanged.
No actual disposable or production database was used for this checkpoint.
