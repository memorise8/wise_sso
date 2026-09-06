# C02/C03 development scaffold — not performance gate evidence

The scheduler in `fastapi-auth-server/ops/phase7/performance_collector.py` owns
scheduled/completed monotonic timestamps, bounded outstanding work and absolute
I/O deadlines. Tests exercise actual private loopback HTTP, including slow headers,
slow bodies, reset/warmup timeout, late remote mutation, malformed framing and
request-path injection. Timeout with uncertain remote drain refuses the block;
it is not a successful cleanup or a complete measurement run.

The module accepts only its constrained loopback action/reset adapter. The
`/phase7/action` and `/phase7/reset` responses are development harness observations,
not independent proof that an Express/FastAPI login flow or database reset ran.
Caller-supplied source/provenance fields are not authenticated by this module.
No production endpoint, database, Redis service or collector was used for these tests.

The repeat checker re-evaluates each of three full-shape documents against the
bound v2 profile, rejects duplicate identities/copied measurement material and
retains per-run document/measurement/provenance digests. These canonical JSON
digests are **not signatures or authenticated original-artifact byte digests**.
All results remain development-only and cannot authorize replacement.

Independent review:

- Code/security: scoped `APPROVE`, no remaining findings.
- Architecture: `WATCH`; safe development scaffold, no remaining code blocker.
- Combined review: `COMMENT`, not a completed C02/C03 or a READY gate.
- Validation: collector20 tests; evaluator20 tests/4 subtests; Ruff, formatting,
  strict mypy and diff checks passed. No actual full-profile run was performed.

Required next integration remains actual ten-flow actions and backend reset/drain,
the owned B01 runtime, G01 authenticated provenance and original-byte bindings,
the real `run-performance-gate.sh` consumer, D5/C01b pre-measurement profile freeze,
and three independently generated 20,000-row runs after final source freeze.
Do not manufacture those runs from the test fixtures or remove the nonqualifying guard.
