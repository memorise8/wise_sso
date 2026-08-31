# Phase 4 provisional evidence

Run `ops/run-phase4-integration.sh` from a shell with no ambient PostgreSQL,
Compose, Docker-context, database, Redis, or port overrides. The runner accepts
only its internally generated `_test_` database on `127.0.0.1:5433`, Redis DB 15
on `127.0.0.1:6380`, and synthetic credentials.

The runner records JUnit/pytest output plus before/after Express identity and
health snapshots. It drops the exact database and DML role, deletes its exact
Redis namespace, and tears down the manifest-validated candidate stack on every
exit path.

`provenance.txt` correlates the run with the Git HEAD, a deterministic hash of
the runtime `src/` tree, and the exact candidate image ID. The black-box smoke
uses an additional guarded Uvicorn listener only on `127.0.0.1:4011`.

This lane is provisional. It does not authorize production credentials, shared
production state, traffic changes, canonical replay, or cutover.
