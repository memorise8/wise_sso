# A09 administrator flow — development only

Date: 2026-09-09 (Asia/Seoul). Builds on `8a7164b` without changing the
Express or FastAPI application, production stores or Prisma schema ownership.

## Implemented boundary

The common flow CLI dispatches the exclusive
`admin-status-role-session-audit` selection to `bin/admin_flow.py`. It supports
single-runtime and both mixed-runtime orderings against already-running disposable
engines. This path does not own their process lifecycle or prove isolation.
The fixed admin fixture, mode-0600 configuration, contract-only environment,
existing Prisma table-presence compatibility preflight and disposable-store guards
remain required. This does not verify column, enum, foreign-key or constraint parity.
Selections are validated before any trial; mixed selections require shared stores.

The new fixture reuses the existing seeded administrator and active password user,
observes the assigned admin role ID, and projects actual state, active refresh-token
hashes and administrator audit records. Wrong command/name bindings are rejected
before mutation. Controls suspend and restore only the fixture administrator to
test stale bearer authorization. Teardown checks observed residual counts.
Cleanup assertions cover all seeded fixture principals, active sessions and admin
audits. Shared seed can retain the canonical `temis` admin/user Role baseline;
global role cleanup is explicitly unverified, and potentially preexisting roles
are never removed by this checkpoint.

The flow reuses existing HTTP and JWT verification helpers. Its sequence checks
directory/audit projections across both route aliases, authorization failures,
role assignment/removal, session revocation, status suspension/reactivation,
self-protection and stale-admin denial. Public receipts contain only fixed assertion
flags and explicit unverified items, not bearer tokens, emails, IDs or raw audits.
Audit comparisons retain all nine observed fields, including record ID, user ID
and UTC-millisecond creation time. Independent expected action semantics distinguish
authorization-denial actors from mutation targets; directory role IDs are matched
against the fixture's observed state.
Each deterministic revocation step starts with exactly one target token, so the
reported revoked count must be the integer one, matching the observed ledger delta.
The performance profile only receives the updated manifest hash; existing sample
counts, thresholds and the four-flow measured corpus are unchanged.

## Proof limits

Local HTTP test servers and fixture doubles verify the driver/evaluator, not the
actual Express/FastAPI applications on PostgreSQL/Redis. Disposable real-engine
execution, approved sample sizes, cross-runtime audit transaction atomicity and
authenticated collection remain unverified. The fixture and CLI guard against
misconfiguration but are not a cryptographically controlled D1 runtime boundary.
A09 and the overall migration remain **NOT_READY**.

## Targeted validation

The three A09 suites passed together: **39 passed / 70 subtests**, with resource
and unraisable-exception warnings treated as errors. The HTTP suite contributes
15 tests / 35 subtests, including all four topologies with RS256 access tokens and
distinct per-runtime HS256 refresh secrets. Hostile cases cover wrong audit user
IDs, duplicate IDs, fabricated timestamps, broken aliases, incorrect state/token
ledgers, malformed response scalars, JWT failures and interrupted restoration.

Integrated A09/A10 regression: **315 passed / 345 subtests**. FastAPI application
regression: **1416 passed / 79 skipped** (one existing Starlette/httpx warning).
All nine changed Python files pass Ruff and formatting; the eight typed files pass
strict mypy. The existing untyped asset test is covered by lint and execution.

Independent final reviews: `a09_code_review` **APPROVE** and `a09_arch_review`
**CLEAR**, with zero unresolved findings in the 15-file A09/A10 checkpoint.
The leader verified all eleven code/test/manifest/profile hashes unchanged across
the final full suite (97.96 seconds). Approval applies only to this development
checkpoint, not A09/A10 parent completion or replacement qualification.
