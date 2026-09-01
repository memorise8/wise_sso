# Phase 6 provisional evidence

Run `ops/run-phase6-integration.sh` only after the Phase 6 source review is stable.
The guarded runner creates a disposable Prisma-migrated database and DML-only role,
uses isolated Redis DB 15, snapshots the production Express containers before and
after, and removes every candidate resource. Generated evidence is provisional and
does not authorize replacement or cutover.
