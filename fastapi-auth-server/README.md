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
