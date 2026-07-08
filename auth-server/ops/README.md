# Auth PostgreSQL Operations

These commands operate the local/current-server PostgreSQL database for the auth server. Secrets are always provided by environment variables; do not commit real passwords or connection URLs.

## Local Docker PostgreSQL

Start a local database owned by the least-privilege application role:

```sh
cd auth-server
export AUTH_DB_ADMIN_PASSWORD='<replace-with-local-admin-password>'
export AUTH_DB_PASSWORD='<replace-with-local-password>'
docker compose up -d postgres
export DATABASE_URL="postgresql://auth_user:${AUTH_DB_PASSWORD}@localhost:${AUTH_DB_PORT:-5432}/auth_db"
npm run prisma:migrate:deploy
```

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
