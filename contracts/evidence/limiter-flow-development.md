# A10 shared limiter regression — development only

Date: 2026-09-09 (Asia/Seoul).

The approved core-flow matrix now maps `global-rate-limit` to the existing
`alternating-shared-rate-limit-boundary` and
`mixed-simultaneous-shared-rate-limit` schedules in `shared-state-core-v1`.
This corrects an omitted mapping; it does not introduce a new limiter or scheduler.
The alternating evaluator also requires the expected `INVALID_CREDENTIALS` code
for pre-limit 401 responses, matching the existing simultaneous prefill check.
Both limiter schedules reject boolean/noninteger counters and TTLs before checking
the exact count and positive TTL, so Python's boolean/numeric equality cannot
produce a passing receipt.
The flow is partial, not complete or qualified. Performance thresholds, sample
counts and scenario definitions are unchanged; the profile only rebinds the
manifest hash.

Focused tests live in `contracts/tests/test_limiter_flow.py`. Their private HTTP
servers and synchronized counter double test the existing evaluator and schedule,
not Express/FastAPI middleware against actual Redis. Request-count boundaries and
an observed positive TTL do not prove clock-driven expiry, Redis atomicity,
trusted proxy/client-IP behavior, every authentication route, production ingress,
approved repeated samples or authenticated collection.

A10 and the overall migration remain **NOT_READY**. No production application,
database, Redis instance or schema owner is changed.

## Validation

Final focused limiter regression: **6 passed / 22 subtests**, with resource and
unraisable-exception warnings treated as errors.
Integrated contracts: **315 passed / 345 subtests**. The focused limiter tests
exercise actual loopback listeners, 20 concurrent requests, boundary errors,
wrong 401/429 codes, mismatched counts, nonpositive TTLs and split counters.
Changed-file Ruff/format and strict mypy passed. The counter double does not
upgrade these results to real Redis or application qualification.

Independent combined A09/A10 review: code **APPROVE**, architecture **CLEAR**;
zero unresolved findings. This approval does not close the listed proof gaps.
