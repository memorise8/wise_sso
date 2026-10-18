# Phase 2 provisional evidence

Run `ops/run-phase2-integration.sh` from the provisional FastAPI worktree. The runner uses only the guarded candidate Compose project and a synthetic per-run PostgreSQL database whose name contains `_test_`.

Evidence index:

- `result.md`: bounded result and overall Phase 2 status
- `runtime-smoke.md`: latest isolated runtime and cleanup observation
- `transaction-lock-map.md`: every planned flow, its actual Express order/isolation/rowcount, and current FastAPI/mixed-runtime status
- `postgres-pytest.txt` and `postgres-junit.xml`: raw isolated PostgreSQL/Prisma/Argon2 results
- `redis-pytest.txt` and `redis-junit.xml`: raw isolated Redis primitive results
- `prisma-semantics.json`: raw synthetic Prisma semantic oracle summary
- `express-before.txt` and `express-after.txt`: production Express invariance snapshots

The generated evidence is development-only. Only the FastAPI failed-login and refresh
rotation persistence primitives are implemented and live-proven here. All other
end-to-end FastAPI flows and every mixed-runtime interleaving remain deferred.

A real backup restore, production refreeze, canonical worktree replay, production
credentials, production routing, canary, cutover, rollback rehearsal, and migration
ownership handoff remain explicitly deferred. Nothing in this directory establishes
replacement readiness.
