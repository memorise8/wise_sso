#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

command -v pg_restore >/dev/null 2>&1 || fail "pg_restore is required but was not found in PATH."
command -v psql >/dev/null 2>&1 || fail "psql is required but was not found in PATH."

backup_file="${1:-}"
restore_url="${AUTH_RESTORE_TEST_DATABASE_URL:-}"

[ -n "$backup_file" ] || fail "usage: AUTH_RESTORE_TEST_DATABASE_URL=... $0 <backup.dump>"
[ -r "$backup_file" ] || fail "backup file is not readable."
[ -n "$restore_url" ] || fail "set AUTH_RESTORE_TEST_DATABASE_URL to a disposable restore-test database URL."

pg_restore \
  --dbname="$restore_url" \
  --clean \
  --if-exists \
  --no-owner \
  --no-acl \
  "$backup_file"

psql "$restore_url" \
  --set=ON_ERROR_STOP=1 \
  --tuples-only \
  --command='SELECT count(*) AS user_count FROM "User";'

printf 'Restore test completed against disposable database.\n'
