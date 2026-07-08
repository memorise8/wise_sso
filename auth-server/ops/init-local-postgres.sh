#!/usr/bin/env bash
set -euo pipefail

auth_db="${AUTH_DB_NAME:-auth_db}"
auth_user="${AUTH_DB_USER:-auth_user}"
auth_password="${AUTH_DB_PASSWORD:-}"

if [ -z "$auth_password" ]; then
  printf 'ERROR: AUTH_DB_PASSWORD is required for local auth database initialization.\n' >&2
  exit 1
fi

case "$auth_db" in
  *[!a-zA-Z0-9_]* | "") printf 'ERROR: AUTH_DB_NAME must contain only letters, numbers, and underscores.\n' >&2; exit 1 ;;
esac

case "$auth_user" in
  *[!a-zA-Z0-9_]* | "") printf 'ERROR: AUTH_DB_USER must contain only letters, numbers, and underscores.\n' >&2; exit 1 ;;
esac

psql \
  --username "$POSTGRES_USER" \
  --dbname postgres \
  --set=ON_ERROR_STOP=1 \
  --set=auth_db="$auth_db" \
  --set=auth_user="$auth_user" \
  --set=auth_password="$auth_password" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L', :'auth_user', :'auth_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'auth_user')\gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'auth_db', :'auth_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'auth_db')\gexec

\connect :auth_db
REVOKE ALL ON DATABASE :"auth_db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"auth_db" TO :"auth_user";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO :"auth_user";
SQL
