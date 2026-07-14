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

# Resolve ports without sourcing the secret-bearing .env. Exported shell values
# win, matching Docker Compose interpolation precedence.
# shellcheck source=scripts/lib/port-config.sh
source "$SCRIPT_DIR/lib/port-config.sh"
BACKEND_PORT="$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "$PROJECT_DIR/.env")"
FRONTEND_PORT="$(vedetta_resolve_port VEDETTA_FRONTEND_PORT 3107 "$PROJECT_DIR/.env")"

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
