#!/bin/sh
set -eu

usage() {
  echo "usage: $0 (--check-only|up|stop|down) <synthetic-fastapi-env-file>" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
action=$1
env_file=$2
case "$action" in
  --check-only|up|stop|down) ;;
  *) usage ;;
esac
[ -f "$env_file" ] || usage

if env | grep -Eq '^(COMPOSE_|DOCKER_HOST=|DOCKER_CONTEXT=|FASTAPI_DEV_ENV_FILE=|WISEACCT_FASTAPI_DEV_ENV_FILE=|AUTH_DB_[A-Z0-9_]*=|DATABASE_URL=|REDIS_URL=|PORT=)'; then
  echo "PROVISIONAL guarded launcher: clear ambient Compose/Docker/SSO overrides" >&2
  exit 3
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_dir=$(CDPATH= cd -- "$(dirname -- "$env_file")" && pwd)
env_path="$env_dir/$(basename -- "$env_file")"
compose_file="$project_dir/docker-compose.dev.yml"
manifest="$script_dir/expected-resources.json"

cleanup_candidate() {
  env -i PATH="$PATH" WISEACCT_FASTAPI_DEV_ENV_FILE="$env_path" \
    docker compose --project-name wiseacct-sso-fastapi-dev --env-file "$env_path" \
    -f "$compose_file" down --volumes --remove-orphans
}

python3 "$script_dir/validate_dev_compose.py" env "$env_path"

resolved=$(mktemp)
trap 'rm -f "$resolved"' EXIT HUP INT TERM
env -i PATH="$PATH" \
  WISEACCT_FASTAPI_DEV_ENV_FILE="$env_path" \
  docker compose \
    --project-name wiseacct-sso-fastapi-dev \
    --env-file "$env_path" \
    -f "$compose_file" \
    config --format json >"$resolved"
python3 "$script_dir/validate_dev_compose.py" resolved "$resolved" "$manifest" "$env_path"

if [ "$action" = "--check-only" ]; then
  echo "PROVISIONAL guarded launcher check passed; no resources were created"
  exit 0
fi

rm -f "$resolved"
trap - EXIT HUP INT TERM
case "$action" in
  up)
    if ! env -i PATH="$PATH" WISEACCT_FASTAPI_DEV_ENV_FILE="$env_path" \
      docker compose --project-name wiseacct-sso-fastapi-dev --env-file "$env_path" \
      -f "$compose_file" up --build --detach --wait --wait-timeout 60; then
      cleanup_candidate
      exit 4
    fi
    runtime=$(mktemp)
    container_names=$(mktemp)
    network_names=$(mktemp)
    volume_names=$(mktemp)
    trap 'rm -f "$runtime" "$container_names" "$network_names" "$volume_names"' EXIT HUP INT TERM
    docker ps -a --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
      --format '{{.Names}}' >"$container_names"
    docker network ls --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
      --format '{{.Name}}' >"$network_names"
    docker volume ls --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
      --format '{{.Name}}' >"$volume_names"
    if ! docker inspect \
      wiseacct-sso-fastapi-dev-app \
      wiseacct-sso-fastapi-dev-postgres \
      wiseacct-sso-fastapi-dev-redis >"$runtime" \
      || ! python3 "$script_dir/validate_dev_compose.py" runtime \
        "$runtime" "$container_names" "$network_names" "$volume_names" "$manifest"; then
      cleanup_candidate
      exit 4
    fi
    echo "PROVISIONAL runtime resources match the exact manifest"
    ;;
  stop)
    exec env -i PATH="$PATH" WISEACCT_FASTAPI_DEV_ENV_FILE="$env_path" \
      docker compose --project-name wiseacct-sso-fastapi-dev --env-file "$env_path" \
      -f "$compose_file" stop
    ;;
  down)
    cleanup_candidate
    ;;
esac
