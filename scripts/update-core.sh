#!/usr/bin/env bash
#
# Vedetta — Update Core Only
#
# Usage:
#   ./scripts/update-core.sh
#
# Pulls latest code, rebuilds Docker images, and restarts Core services.
# Does NOT touch the sensor.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Read a pinned host port from .env (scripts/gen-env.sh may have shifted it off
# the default when the default was already taken on this host); fall back to the
# documented default. Grep the exact key rather than sourcing .env, which holds
# secrets and arbitrary values.
env_port() {
  local key="$1" default="$2" val=""
  [ -f "$PROJECT_DIR/.env" ] && val="$(grep -E "^${key}=" "$PROJECT_DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
  printf '%s' "${val:-$default}"
}
BACKEND_PORT="$(env_port VEDETTA_BACKEND_PORT 8080)"
FRONTEND_PORT="$(env_port VEDETTA_FRONTEND_PORT 3107)"

echo "═══════════════════════════════════════════"
echo "  Vedetta — Core Update"
echo "═══════════════════════════════════════════"
echo ""

cd "$PROJECT_DIR"

# --- Pull latest code ---
echo "▸ Pulling latest from git..."
git pull --rebase
echo ""

# --- Rebuild and restart ---
echo "▸ Stopping Core services..."
docker compose down
echo ""

echo "▸ Rebuilding Docker images..."
docker compose build --no-cache backend frontend
echo ""

echo "▸ Starting Core services..."
docker compose up -d
echo ""

# Wait for backend health check
echo "▸ Waiting for backend to become healthy..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:${BACKEND_PORT}/healthz" > /dev/null 2>&1; then
        echo "  Backend healthy."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "  WARNING: Backend did not become healthy within 30s."
    fi
    sleep 1
done

echo ""
echo "═══════════════════════════════════════════"
echo "  Core update complete."
echo "  Dashboard: http://localhost:${FRONTEND_PORT}"
echo "  API:       http://localhost:${BACKEND_PORT}/api/v1/status (read/admin bearer required)"
echo "═══════════════════════════════════════════"
