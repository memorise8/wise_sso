#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

command -v pg_dump >/dev/null 2>&1 || fail "pg_dump is required but was not found in PATH."

database_url="${AUTH_DATABASE_URL:-${DATABASE_URL:-}}"
if [ -z "$database_url" ]; then
  fail "set AUTH_DATABASE_URL or DATABASE_URL to the auth PostgreSQL connection URL."
fi

backup_dir="${AUTH_BACKUP_DIR:-./backups}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
output_file="${1:-${backup_dir}/auth_db-${timestamp}.dump}"

mkdir -p "$(dirname "$output_file")"

pg_dump \
  --dbname="$database_url" \
  --format=custom \
  --no-owner \
  --no-acl \
  --file="$output_file"

chmod 600 "$output_file"
printf 'Backup written to %s\n' "$output_file"
