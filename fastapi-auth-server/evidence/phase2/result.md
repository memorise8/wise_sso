# Phase 2 provisional isolated integration result

- Isolated synthetic subset: PASS
- Overall Phase 2: **NOT COMPLETE**
- Scope: synthetic PostgreSQL database with `_test_` in its name on `127.0.0.1:5433`
- Prisma owner: checked-in migrations applied with `prisma migrate deploy`
- Runtime role: DML-only; `CREATE TABLE` denied with SQLSTATE `42501`
- Live DB proofs: catalog mirror, Prisma semantic oracle including exact TIMESTAMP(3) roundtrip, failed-login 4/5/20 concurrency, refresh 20-way single-success, and Argon2 Node/Python interoperability
- Live Redis proofs: NX+EX, exact-value consume, rate-limit count/TTL, consume races, and fail-closed unavailable endpoint
- Backup proof: synthetic-only custom-format dump, disposable `_test_` restore, and read-only application-role smoke
- Cleanup: exact test database, runtime role, Phase 2 Redis prefix, Compose containers/network/volume removed
- Express: container IDs, start times, restart counts, health states, and HTTP 200 unchanged
- Deferred: all remaining transaction-map flows, real production backup restore, shared Express/FastAPI runtime, production data/credentials, and production-like mixed-writer interleavings

This evidence is PROVISIONAL and is not production replacement or cutover approval.
