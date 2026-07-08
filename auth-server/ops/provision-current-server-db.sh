#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

command -v psql >/dev/null 2>&1 || fail "psql is required but was not found in PATH."

admin_url="${AUTH_DB_ADMIN_URL:-}"
auth_password="${AUTH_DB_PASSWORD:-}"
auth_db="${AUTH_DB_NAME:-auth_db}"
auth_user="${AUTH_DB_USER:-auth_user}"

[ -n "$admin_url" ] || fail "set AUTH_DB_ADMIN_URL to a privileged PostgreSQL maintenance connection URL."
[ -n "$auth_password" ] || fail "set AUTH_DB_PASSWORD to the password for the auth_user role."

case "$auth_db" in
  *[!a-zA-Z0-9_]* | "") fail "AUTH_DB_NAME must contain only letters, numbers, and underscores." ;;
esac

case "$auth_user" in
  *[!a-zA-Z0-9_]* | "") fail "AUTH_DB_USER must contain only letters, numbers, and underscores." ;;
esac

psql "$admin_url" \
  --set=ON_ERROR_STOP=1 \
  --set=auth_db="$auth_db" \
  --set=auth_user="$auth_user" \
  --set=auth_password="$auth_password" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'auth_user', :'auth_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'auth_user')\gexec

SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'auth_user', :'auth_password')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'auth_user')\gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'auth_db', :'auth_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'auth_db')\gexec
SQL

psql "$admin_url" \
  --set=ON_ERROR_STOP=1 \
  --set=auth_db="$auth_db" \
  --set=auth_user="$auth_user" <<'SQL'
\connect :auth_db
REVOKE ALL ON DATABASE :"auth_db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"auth_db" TO :"auth_user";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO :"auth_user";
SQL

printf 'Provisioned PostgreSQL database %s and role %s.\n' "$auth_db" "$auth_user"
