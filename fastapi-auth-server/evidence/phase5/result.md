# Phase 5 provisional isolated integration result

- Guarded real PostgreSQL/Redis lane: PASS
- Overall migration: **NOT REPLACEMENT READY**
- Scope: disposable PostgreSQL `_test_` database on `127.0.0.1:5433`; isolated Redis DB 15 on `127.0.0.1:6380`; fake mail/provider only
- Schema owner: checked-in Prisma migrations; Python runtime role received DML only; DDL denied with SQLSTATE `42501`
- Phase 5 proofs: hash-only 24-hour verification and 1-hour password-reset records; consume-then-domain-failure commit boundaries; mail ordering; local STARTTLS and implicit-TLS/Resend fake-SMTP delivery/reject/timeout/no-STARTTLS boundaries; self-signed local HTTPS provider TLS rejection; 20-way single-consumer confirmation/reset races; default role activation; pending-password attach; reset counter clearing and refresh revocation; OAuth state 600-second destructive wrong-provider consume; handoff hashed-key 120-second binding-preserving raw CAS; Node↔Python JSON consumption; OAuth identity attach/pending replacement/subject reservation/same-provider race; real Express/Prisma↔FastAPI/SQLAlchemy mixed-writer same-provider, verified-email attach, and subject-reservation races; exchange consume-before-token-issue failure
- Network: no external provider or mail calls; localhost candidate services only
- Cleanup: exact test database, DML role, Compose containers/network/volume removed; zero candidate resources remain
- Express: container IDs, start times, restart counts, health states, and HTTP 200 unchanged

This evidence is PROVISIONAL and is not production replacement or cutover approval.
