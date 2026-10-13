#!/usr/bin/env bash
# Shared helpers for local start/stop scripts.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="${ROOT_DIR}/.run"
LOG_DIR="${RUN_DIR}/logs"
PID_DIR="${RUN_DIR}/pids"

APP_PORT="${PORT:-5050}"
PY_BIN="${AI_SPM_PYTHON:-}"
if [[ -z "${PY_BIN}" ]]; then
  if [[ -x /tmp/ai-spm-py/bin/python ]]; then
    PY_BIN=/tmp/ai-spm-py/bin/python
  else
    PY_BIN="$(command -v python3 || true)"
  fi
fi

ensure_run_dirs() {
  mkdir -p "${LOG_DIR}" "${PID_DIR}"
}

load_dotenv() {
  local env_file="${ROOT_DIR}/.env"
  if [[ ! -f "${env_file}" ]]; then
    echo "warn: ${env_file} not found — using process environment only" >&2
    return 0
  fi
  set -a
  # shellcheck disable=SC1090
  source "${env_file}"
  set +a
  APP_PORT="${PORT:-5050}"
}

port_in_use() {
  local port="$1"
  lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
}

kill_port() {
  local port="$1"
  local pids
  local attempt
  for attempt in 1 2 3; do
    pids="$(lsof -nP -iTCP:"${port}" -sTCP:LISTEN -t 2>/dev/null || true)"
    [[ -z "${pids}" ]] && return 0
    echo "stopping listeners on :${port} (${pids}) [attempt ${attempt}]"
    # shellcheck disable=SC2086
    if [[ "${attempt}" -lt 3 ]]; then
      kill ${pids} 2>/dev/null || true
    else
      kill -9 ${pids} 2>/dev/null || true
    fi
    sleep 1
  done
  pids="$(lsof -nP -iTCP:"${port}" -sTCP:LISTEN -t 2>/dev/null || true)"
  if [[ -n "${pids}" ]]; then
    echo "warn: still listening on :${port} (${pids})" >&2
    return 1
  fi
}

write_pid() {
  local name="$1"
  local pid="$2"
  echo "${pid}" > "${PID_DIR}/${name}.pid"
}

read_pid() {
  local name="$1"
  local file="${PID_DIR}/${name}.pid"
  [[ -f "${file}" ]] && cat "${file}" || true
}

stop_pid_file() {
  local name="$1"
  local file="${PID_DIR}/${name}.pid"
  if [[ ! -f "${file}" ]]; then
    return 0
  fi
  local pid
  pid="$(cat "${file}" 2>/dev/null || true)"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    echo "stopping ${name} (pid ${pid})"
    kill "${pid}" 2>/dev/null || true
    sleep 1
    if kill -0 "${pid}" 2>/dev/null; then
      kill -9 "${pid}" 2>/dev/null || true
    fi
  fi
  rm -f "${file}"
}

wait_http() {
  local url="$1"
  local label="$2"
  local attempts="${3:-40}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS -o /dev/null "${url}" 2>/dev/null; then
      echo "ok  ${label} → ${url}"
      return 0
    fi
    sleep 0.5
  done
  echo "fail ${label} did not become ready: ${url}" >&2
  return 1
}
