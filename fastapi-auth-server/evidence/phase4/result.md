# Phase 4 provisional isolated integration result

- Guarded real PostgreSQL/Redis lane: PASS
- Overall Phase 4: **NOT COMPLETE**
- Scope: synthetic PostgreSQL `_test_` database on `127.0.0.1:5433` and Redis DB 15 on `127.0.0.1:6380`
- Schema owner: checked-in Prisma migrations; Python runtime role received DML only and DDL was denied with SQLSTATE `42501`
- Auth proofs: normalized registration, Node↔Python JWT/Argon2 and Zod-oracle compatibility, hashed-only refresh persistence, access-token `/users/me`, 20-way refresh single success, deterministic refresh/status mutation schedules, logout 204, exact five-failure/15-minute lock, Redis rate count/TTL/429, audit order/secret absence, and black-box TCP login→me→refresh→logout
- Source/image correlation: `provenance.txt`
- Cleanup: exact test database, DML role, Phase 4 Redis prefix, Compose containers/network/volume removed
- Express: container IDs, start times, restart counts, health states, and HTTP 200 unchanged
- Deferred: Express↔FastAPI mixed-writer refresh/logout and account-status schedules, production data/credentials, canonical refreeze/replay, and cutover

This evidence is PROVISIONAL and is not production replacement or cutover approval.
