#!/usr/bin/env bash
# Start AI-SPM locally: optional Phoenix, Python microservices, Node app (:5050).
#
# Usage:
#   ./scripts/start-local.sh
#   START_PHOENIX=true ./scripts/start-local.sh
#   SKIP_MICROSERVICES=true ./scripts/start-local.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ensure_run_dirs
load_dotenv
cd "${ROOT_DIR}"

START_PHOENIX="${START_PHOENIX:-false}"
SKIP_MICROSERVICES="${SKIP_MICROSERVICES:-false}"
SKIP_APP="${SKIP_APP:-false}"

echo "=== AI-SPM local startup ==="
echo "root: ${ROOT_DIR}"
echo "port: ${APP_PORT}"
echo "python: ${PY_BIN:-none}"

# --- Postgres sanity ---
if command -v pg_isready >/dev/null 2>&1; then
  if ! pg_isready -h "${PGHOST:-localhost}" -p "${PGPORT:-5432}" -U "${PGUSER:-ai_spm_user}" >/dev/null 2>&1; then
    echo "warn: Postgres not ready at ${PGHOST:-localhost}:${PGPORT:-5432} — app may fail until DB is up" >&2
  else
    echo "ok  postgres"
  fi
fi

# --- Phoenix (optional) ---
if [[ "${START_PHOENIX}" == "true" ]]; then
  if command -v docker >/dev/null 2>&1; then
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^ai-spm-phoenix$'; then
      if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^ai-spm-phoenix$'; then
        docker start ai-spm-phoenix >/dev/null
      else
        docker run -d --name ai-spm-phoenix -p 6006:6006 arizephoenix/phoenix:latest >/dev/null
      fi
    fi
    wait_http "http://127.0.0.1:6006/" "phoenix" 60 || true
  else
    echo "warn: docker not available — skip Phoenix container (collector may already be running)" >&2
  fi
fi

# --- Python microservices ---
start_microservice() {
  local name="$1"
  local port="$2"
  local entry="$3"
  if [[ "${SKIP_MICROSERVICES}" == "true" ]]; then
    return 0
  fi
  if [[ -z "${PY_BIN}" || ! -x "${PY_BIN}" ]]; then
    echo "warn: no python runtime — skip ${name}" >&2
    return 0
  fi
  if port_in_use "${port}"; then
    echo "ok  ${name} already on :${port}"
    return 0
  fi
  echo "starting ${name} on :${port}"
  (
    cd "${ROOT_DIR}"
    PORT="${port}" "${PY_BIN}" "${entry}" \
      >"${LOG_DIR}/${name}.log" 2>&1 &
    write_pid "${name}" $!
  )
}

start_microservice "ai-scanner" 8001 "microservices/ai-scanner/main.py"
start_microservice "data-integrity" 8002 "microservices/data-integrity/main.py"
start_microservice "wiz-integration" 8003 "microservices/wiz-integration/main.py"
start_microservice "compliance-engine" 8004 "microservices/compliance-engine/main.py"

if [[ "${SKIP_MICROSERVICES}" != "true" ]]; then
  wait_http "http://127.0.0.1:8001/health" "ai-scanner" 40 || true
  wait_http "http://127.0.0.1:8002/health" "data-integrity" 40 || true
  wait_http "http://127.0.0.1:8003/health" "wiz-integration" 40 || true
  wait_http "http://127.0.0.1:8004/health" "compliance-engine" 40 || true
fi

# --- Node app ---
if [[ "${SKIP_APP}" == "true" ]]; then
  echo "SKIP_APP=true — not starting Node gateway"
  exit 0
fi

if port_in_use "${APP_PORT}"; then
  echo "ok  app already listening on :${APP_PORT}"
else
  echo "starting Node app (npm run dev) on :${APP_PORT}"
  (
    cd "${ROOT_DIR}"
    nohup npm run dev >"${LOG_DIR}/app.log" 2>&1 &
    write_pid "app" $!
  )
fi

wait_http "http://127.0.0.1:${APP_PORT}/api/health" "app" 60

echo
echo "AI-SPM is up"
echo "  UI/API:  http://localhost:${APP_PORT}"
echo "  Phoenix: ${PHOENIX_COLLECTOR_ENDPOINT:-http://localhost:6006} (if started/running)"
echo "  logs:    ${LOG_DIR}"
echo "  stop:    ./scripts/stop-local.sh"
