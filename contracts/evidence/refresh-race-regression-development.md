# A08 refresh-race regression — development only

The existing `shared_state.py` execution path already contains the 20-way mixed
refresh race and both logout/refresh schedules. This checkpoint adds focused
regressions; it does not introduce a second scheduler or change the application.

`test_refresh_race_flow.py` drives the existing scheduling code through two real
loopback HTTP test servers. Twenty handlers synchronize before a lock-protected
synthetic rotation, producing one winner and nineteen generic failures. The test
also checks both runtime role counts and actual request-lifetime overlap.

Hostile regressions reject zero/two winners, non-generic losers, incorrect
replacement/original token hashes and non-generic original-token replay. Both
registered logout/refresh schedules exercise both permitted final outcomes.
Those latter cases use deterministic mocked results to test the evaluator.

These servers are Python doubles, not Express/FastAPI app instances. The ledger
snapshot is a test adapter, and tokens are synthetic strings, not proof of JWT
cryptography or PostgreSQL/Redis transactions. No DB critical-section ordering,
approved repeated-sample completion or authenticated qualification is claimed.
A08 remains open and overall replacement status remains **NOT_READY**.

Independent code review: **APPROVE**. Independent architecture review: **CLEAR**.
Both reviews apply only to this scheduler/evaluator regression slice.

The test helper was repaired before approval: only started servers receive
`shutdown`, all acquired sockets close, the barrier is aborted, non-daemon
request threads are tracked/drained, accepted sockets have timeouts, and cleanup
failures remain attached to the original error. An injected second-thread-start
failure exercises the previously hanging startup path.

Targeted verification: `6 passed, 9 subtests passed`; Ruff check/format and strict
mypy passed. Frozen test SHA-256:
`fc4dc83aed7f521f3ba495d4170ddd34bcd1e120969bf6c404aaa1a11153e609`.
The shared-state runner is unchanged, SHA-256:
`1d832d5e34ef2282e71d2f9fd60e4b5ffda1288b3bb20f4e2fc900191fd026d5`.

Final complete contracts regression: `269 passed, 253 subtests passed`
(80.06 seconds), including this file and the committed provider extension.
Both hashes above were unchanged across the run. The same-turn FastAPI baseline
was `1416 passed, 79 skipped`; no application source changed afterward.
