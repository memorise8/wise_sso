# WiseAcct SSO FastAPI — PROVISIONAL Phase 1

> **PROVISIONAL / NOT FOR PRODUCTION.** This worktree is based on a pre-refreeze
> baseline. It must not receive production traffic, credentials, databases,
> Redis instances, volumes, or container names.

This directory contains only the isolated Phase 1 FastAPI foundation. The
current Express service remains the production system of record.

## Local verification

Use the checkpointed uv release; the system uv version is intentionally not
used to create or update the lockfile.

```sh
uvx --from 'uv==0.12.5' uv sync --frozen
uvx --from 'uv==0.12.5' uv run --frozen pytest
uvx --from 'uv==0.12.5' uv run --frozen ruff check .
uvx --from 'uv==0.12.5' uv run --frozen mypy
```

All Compose access must go through the guarded launcher with an explicitly
supplied synthetic-only env file. Direct `docker compose` invocation is not a
supported development path. Do not use the existing Express `.env`.

```sh
./ops/dev-compose.sh --check-only .env.example
```

The launcher rejects ambient Compose, Docker target, database, Redis, port, and
project overrides; validates the env allowlist; renders Compose; and checks the
exact resolved resource manifest before any action. Future isolated startup is
`./ops/dev-compose.sh up .env.example`, but no Compose start is part of
provisional Phase 1 verification.

## Dormant operations candidates

`wiseacct_sso.ops` contains cutover-continuity candidates, not an active scheduler
or an approved production operations package. Nothing in the application invokes
these commands. Express remains the operations owner and Prisma the sole schema
authority. See the [successor inventory](../contracts/evidence/ops-successor-development-inventory.md)
for item-by-item verification gaps.

The default-role backfill entrypoint is `python -m wiseacct_sso.ops.default_role_backfill`.
It accepts no arguments and is a mutating command, not a dry run. It uses the
validated application configuration, including the configured TEMIS default role;
it does not silently choose a role. It seeds required roles and assigns only users
with no existing role in one serializable, bounded-retry transaction. Output contains
the role and inserted counts, not credentials. Its unit/SQL verification does not
authorize running it against production; disposable PostgreSQL validation and an
approved single-owner cutover are still required.

The split-identity repair candidate is `python -m wiseacct_sso.ops.merge_split_identities`.
Its default is read-only discovery; only explicit `--apply` mutates data, with an
optional `--email` filter. It retains the Express Google/split-account criteria,
credential transfer, audit and Prisma cascade behavior. Each candidate is locked
and revalidated inside a serializable transaction. Deliberate safety differences
are that stale candidates are skipped visibly and `mergedCount` reports actual
commits, with a separate `staleCount`. Dry-run output contains candidate identities
and must stay private. Disposable database validation and operational approval are
still required; neither command is invoked by the application.
