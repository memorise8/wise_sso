# Phase 5 guarded integration evidence

Run `ops/run-phase5-integration.sh` from an environment without ambient Compose, Docker,
database, Redis, or port overrides. The runner creates only a disposable `_test_` database,
a DML-only role, and a fresh candidate Compose stack, while snapshotting the existing Express
containers and health endpoint before and after. `result.md` is authoritative only when the
runner completed cleanup and wrote `PASS`.
