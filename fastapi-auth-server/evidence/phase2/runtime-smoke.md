# Phase 2 provisional runtime smoke

## Latest isolated observation

The latest isolated runtime smoke completed on 2026-08-31 at approximately 11:32 KST.

| Check | Observed result |
| --- | --- |
| Candidate project | Guarded Compose project `wiseacct-sso-fastapi-dev` only |
| Candidate app image | `sha256:029c38ae6697dc48310df10a9cabd1386b79e7716e12bb2164808d7cec1da5b3` |
| App process identity | Non-root image user `fastapi-sso` |
| App container | Healthy; restart count `0` |
| PostgreSQL container | Healthy; restart count `0` |
| Redis container | Healthy; restart count `0` |
| `GET /healthz` | HTTP `200` |
| `GET /readyz` | HTTP `200`; the runtime readiness check reached the isolated PostgreSQL dependency |
| Default FastAPI test gate | `68 passed, 12 skipped`; live integrations run only through the guarded runner |
| Guarded live integration gate | PostgreSQL/Prisma/Argon2 `9 passed`; Redis `5 passed` |
| Express production path | Before/after snapshots were byte-identical and Express `/healthz` remained HTTP `200` |

The image ID and configured non-root user were re-read from the local image after the
runtime smoke. The guarded integration counts are preserved in the PostgreSQL and Redis
JUnit/text artifacts; the Express before/after snapshots are preserved in
`express-before.txt` and `express-after.txt` without reproducing their container
identifiers here.

## Exact cleanup result

The runner removed the exact synthetic test database, exact temporary DML-only role,
and exact per-run Redis key prefix. The guarded launcher then removed the candidate
Compose containers, network, and volume. A post-run label query found no remaining
container, network, or volume belonging to `wiseacct-sso-fastapi-dev`.

No production container, route, database, Redis namespace, credential, or volume was
changed. The existing Express app, PostgreSQL, and Redis retained the same identities,
start times, healthy states, and restart count `0` across the run.

## Deferred gates

This smoke is provisional development evidence only. The following work did not run:

- restore of a real backup and read-only smoke against the restored data;
- shared Express/FastAPI DB or Redis interleaving;
- production prerequisite deployment and refreeze;
- creation/replay and verification in the canonical FastAPI worktree;
- production credentials, routing, canary, cutover, or rollback rehearsal.

Therefore this smoke does not establish Phase 2 completion, production readiness, or
that FastAPI can replace Express.
