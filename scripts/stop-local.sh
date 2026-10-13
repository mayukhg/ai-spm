#!/usr/bin/env bash
# Stop AI-SPM local processes started by start-local.sh (and any stray listeners).
#
# Usage:
#   ./scripts/stop-local.sh
#   STOP_PHOENIX=true ./scripts/stop-local.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ensure_run_dirs
load_dotenv
cd "${ROOT_DIR}"

STOP_PHOENIX="${STOP_PHOENIX:-false}"

echo "=== AI-SPM local shutdown ==="

# Prefer SIGTERM via recorded PIDs (gives Node a chance to flush Phoenix + stop resident agent)
stop_pid_file "app"
stop_pid_file "ai-scanner"
stop_pid_file "data-integrity"
stop_pid_file "wiz-integration"
stop_pid_file "compliance-engine"

# Clear listeners that outlived pid files (npm wrapper, orphans, prior manual starts)
app_stop_ok=0
kill_port "${APP_PORT}" && app_stop_ok=1 || true
for port in 8001 8002 8003 8004; do
  kill_port "${port}" || true
done

if [[ "${STOP_PHOENIX}" == "true" ]] && command -v docker >/dev/null 2>&1; then
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^ai-spm-phoenix$'; then
    echo "stopping phoenix container (ai-spm-phoenix)"
    docker stop ai-spm-phoenix >/dev/null || true
  fi
fi

if [[ "${app_stop_ok}" -ne 1 ]] || port_in_use "${APP_PORT}"; then
  echo "error: something still listening on :${APP_PORT}" >&2
  lsof -nP -iTCP:"${APP_PORT}" -sTCP:LISTEN 2>/dev/null || true
  exit 1
fi

echo "ok  local stack stopped (port ${APP_PORT} free)"
echo "    Phoenix left running unless STOP_PHOENIX=true"
