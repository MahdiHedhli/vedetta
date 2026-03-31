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
    if curl -sf http://localhost:8080/healthz > /dev/null 2>&1; then
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
echo "  Dashboard: http://localhost:3107"
echo "  API:       http://localhost:8080/api/v1/status"
echo "═══════════════════════════════════════════"
