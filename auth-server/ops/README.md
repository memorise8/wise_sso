# Auth Server Operations

These commands operate the local/current-server PostgreSQL and Redis dependencies for the auth server. Secrets are always provided by environment variables; do not commit real passwords or connection URLs.

## Local Docker Dependencies

Start the local database owned by the least-privilege application role and the Redis state store required before the Node server can listen:

```sh
cd auth-server
export AUTH_DB_ADMIN_PASSWORD='<replace-with-local-admin-password>'
export AUTH_DB_PASSWORD='<replace-with-local-password>'
docker compose up -d postgres redis
export DATABASE_URL="postgresql://auth_user:${AUTH_DB_PASSWORD}@localhost:${AUTH_DB_PORT:-5432}/auth_db"
export REDIS_URL="redis://127.0.0.1:${AUTH_REDIS_PORT:-6379}"
npm run prisma:migrate:deploy
```

The checked-in Compose defaults publish PostgreSQL and Redis only on loopback:
`AUTH_DB_HOST=127.0.0.1` and `AUTH_REDIS_HOST=127.0.0.1`. Override those host
variables only for a deliberately firewalled private-interface deployment.

Use `REDIS_URL=redis://127.0.0.1:6379` when running Node on the host against the Compose-published port. Use `REDIS_URL=redis://redis:6379` only when the Node app itself runs inside the Compose network.

Stop it when finished:

```sh
cd auth-server
docker compose down
```

Remove local database data only when you intentionally want a fresh database:

```sh
cd auth-server
docker compose down -v
```

## Current-Server PostgreSQL

Run this from the server that hosts PostgreSQL. `AUTH_DB_ADMIN_URL` must be a privileged maintenance connection, for example a local socket or a temporary admin URL. The script creates or updates `auth_user`, creates `auth_db` if needed, revokes public database access, and grants only the privileges the auth server needs for Prisma migrations and normal operation.

```sh
cd auth-server
export AUTH_DB_ADMIN_URL='postgresql://postgres:<admin-password>@127.0.0.1:5432/postgres'
export AUTH_DB_PASSWORD='<replace-with-auth-user-password>'
./ops/provision-current-server-db.sh
```

Use the resulting application connection for the auth server and Prisma:

```sh
export DATABASE_URL='postgresql://auth_user:<auth-user-password>@127.0.0.1:5432/auth_db'
npm run prisma:migrate:deploy
```

## Backup

Backups use PostgreSQL custom format so they can be restore-tested with `pg_restore`.

```sh
cd auth-server
export AUTH_DATABASE_URL='postgresql://auth_user:<auth-user-password>@127.0.0.1:5432/auth_db'
export AUTH_BACKUP_DIR='/var/backups/wiseacct-auth'
npm run ops:backup
```

The backup script fails before running `pg_dump` when neither `AUTH_DATABASE_URL` nor `DATABASE_URL` is set. Its error message does not print connection values.

## Restore Test

Always restore into a disposable database, never `auth_db`.

```sh
createdb auth_db_restore_test
export AUTH_RESTORE_TEST_DATABASE_URL='postgresql://auth_user:<auth-user-password>@127.0.0.1:5432/auth_db_restore_test'
npm run ops:restore-test -- /var/backups/wiseacct-auth/auth_db-YYYYMMDDTHHMMSSZ.dump
dropdb auth_db_restore_test
```

## Firewall Notes

For a single current-server MVP, bind PostgreSQL to localhost or a private interface. Do not expose port `5432` publicly. If another host must reach PostgreSQL, allow only that host's private IP at the OS firewall or cloud security group and keep TLS/password authentication enabled.

## Auth Server Runtime Checks

Use separate probes for process liveness and database readiness:

```sh
curl -i http://127.0.0.1:4000/healthz
curl -i http://127.0.0.1:4000/readyz
```

`/healthz` only proves the HTTP process is alive. `/readyz` checks PostgreSQL and should be the load balancer readiness gate.

## Phase 0 Candidate Image Smoke

First commit the exact image inputs (`Dockerfile`, `package*.json`, `tsconfig`,
`prisma`, `src`, and `public`) so they have no tracked or untracked changes, then
build with an explicit candidate tag:

```sh
cd auth-server
npm run build:phase0-image -- wiseacct-sso-auth:phase0-<revision>
```

The build wrapper hashes `git ls-tree -r HEAD` for exactly those inputs, passes
`SOURCE_REVISION` and `SOURCE_INPUTS_SHA256` as build arguments, applies OCI
revision and source-input labels, and verifies them on the resolved image ID.

Run that candidate against disposable PostgreSQL 16 and Redis 7.4 without
changing the current Compose stack. The harness fails closed if its explicit
`wiseacct-phase0-smoke-*` resource names or loopback ports `4001`/`5433` are in
use, creates a Docker internal network with no external egress, generates a new
ephemeral RSA keypair, refresh secret, and database password for every run,
applies migrations with the pinned local Prisma binary, and removes only
resources whose captured ID and per-run ownership label both match. It never
reads `auth-server/.env`; OAuth and external mail delivery are disabled and all
remaining application configuration is synthetic. The resolved immutable image
ID is used for launch and compared with the running container image ID. The
smoke harness independently requires the same clean HEAD inputs and label
values, then compares the local Prisma schema hash with both schema copies in
the running image.

```sh
cd auth-server
npm run test:phase0-image-smoke -- <current-candidate-image>
```

Sanitized evidence is atomically written only to
`contracts/evidence/phase0-image-smoke.txt`. The image argument is mandatory so
stale tags cannot be tested accidentally. Evidence includes the source SHA,
Dockerfile and lockfile hashes, resolved image IDs, running image IDs, and owned
resource IDs, but never generated secret values.

On failure, bounded tails of Docker launch, relay, Prisma, app, and JWKS logs plus
candidate/PostgreSQL/Redis state and Docker log tails are sanitized into the
fixed mode-600 `contracts/evidence/phase0-image-smoke-diagnostics.txt`. Exact
synthetic DB credentials, URI passwords, PEM blocks, JWTs, and generic
credential/token patterns are redacted before publication. A successful run
atomically replaces that artifact with an `EMPTY` success marker.

The harness requires Linux with readable same-user `/proc/<pid>/environ`, Bash,
Docker Engine with Linux bridge networking, Node.js, `curl`, `ss`, GNU
`readlink`/`stat`/`sha256sum`/`grep`, and the repository's installed pinned
Prisma binary. Docker does not publish ports from the internal network. Instead,
short-lived host Node.js TCP relays, identified by PID and per-run ownership
environment, bind only `127.0.0.1:4001` and `127.0.0.1:5433` and forward to the
captured internal container addresses. The candidate remains attached only to
the internal Docker network and therefore receives no external-egress network.
PostgreSQL is limited to 512 MiB/1 CPU/256 PIDs, Redis to 128 MiB/0.5 CPU/128
PIDs, and the candidate app to 512 MiB/1 CPU/256 PIDs. The app also drops all
capabilities, enables `no-new-privileges`, uses a read-only root filesystem, and
gets only a bounded, non-executable `/tmp` tmpfs. The harness inspects and
records these effective settings rather than trusting command arguments alone.

## TEMIS Client Policy

Production `AUTH_CLIENTS_JSON` must keep redirect authorization separate from CORS:

```sh
export AUTH_CLIENTS_JSON='[{"clientId":"temis","audience":"temis","allowedRedirectUris":["https://financenow.kr/auth/callback","https://temis.me/auth/callback","https://ti.temis.me/auth/callback"],"allowedOrigins":["https://financenow.kr"],"defaultRole":{"serviceKey":"temis","name":"user"}}]'
```

`allowedRedirectUris` must exactly match the TEMIS backend/BFF callback that exchanges handoff codes. `allowedOrigins` is only for browser CORS.

The checked-in `.env.example` keeps `OAUTH_ENABLED_PROVIDERS=""` so local config parsing works without real provider credentials. Enable Google only after setting `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI`:

```sh
export OAUTH_ENABLED_PROVIDERS='google'
```

## First Admin Bootstrap

Create the first admin from an existing `ACTIVE` user. There is no public bootstrap endpoint and no env variable grants admin rights.

```sh
cd auth-server
npm run ops:grant-admin -- --email admin@example.com
```

The command grants `temis:admin`, writes audit reason `OPS_BOOTSTRAP_ADMIN`, and revokes the user's existing refresh tokens so future tokens carry current roles.

## Audit Log Retention Cleanup

Audit cleanup is dry-run by default and only reports the row count and cutoff timestamp:

```sh
cd auth-server
npm run ops:cleanup-audit-logs
npm run ops:cleanup-audit-logs -- --retention-days 180
```

Deletion requires `--execute`. The cleanup deletes only `AuditLog` rows with `createdAt` older than the cutoff:

```sh
cd auth-server
npm run ops:cleanup-audit-logs -- --retention-days 180 --execute
```

## QA Fixture

For local admin approval QA, seed deterministic users and tokens after PostgreSQL/Redis are available and migrations have run:

```sh
cd auth-server
npm run qa:seed-temis-admin-flow
set -a
. ../.omo/evidence/temis-sso-p0-auth-hardening/qa-fixture.env
set +a
```

Do not use fixture output in production. The fixture is only for local HTTP checks of admin list/status/role/session flows.
