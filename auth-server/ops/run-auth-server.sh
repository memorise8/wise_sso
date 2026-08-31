#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$APP_DIR/.auth-server.pid"
LOG_DIR="$APP_DIR/logs"
LOG_FILE="$LOG_DIR/auth-server.log"
PORT="${PORT:-4000}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"

is_running() {
  [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

start_server() {
  if is_running; then
    echo "Auth server is already running. pid=$(cat "$PID_FILE")"
    return
  fi

  mkdir -p "$LOG_DIR"
  cd "$APP_DIR"
  npm run build
  setsid bash -c 'echo "$$" >"$1"; exec env REDIS_URL="$2" node dist/src/server.js >>"$3" 2>&1' _ "$PID_FILE" "$REDIS_URL" "$LOG_FILE" &
  sleep 2

  if ! is_running; then
    echo "Auth server failed to start. Last logs:"
    tail -n 80 "$LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
  fi

  echo "Auth server started. pid=$(cat "$PID_FILE") port=$PORT log=$LOG_FILE"
}

stop_server() {
  if ! is_running; then
    echo "Auth server is not running."
    rm -f "$PID_FILE"
    return
  fi

  local pid
  pid="$(cat "$PID_FILE")"
  kill "$pid"
  rm -f "$PID_FILE"
  echo "Auth server stopped. pid=$pid"
}

status_server() {
  if is_running; then
    echo "Auth server is running. pid=$(cat "$PID_FILE") port=$PORT log=$LOG_FILE"
    return
  fi

  echo "Auth server is not running."
  rm -f "$PID_FILE"
}

case "${1:-start}" in
  start)
    start_server
    ;;
  stop)
    stop_server
    ;;
  restart)
    stop_server
    start_server
    ;;
  status)
    status_server
    ;;
  logs)
    tail -n "${2:-120}" "$LOG_FILE"
    ;;
  *)
    echo "Usage: $0 [start|stop|restart|status|logs]"
    exit 2
    ;;
esac
