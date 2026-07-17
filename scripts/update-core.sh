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

# Wait for backend READINESS, not mere liveness. /readyz returns 200 only once
# migrations have applied, the schema head matches this build, and the DB passes its
# integrity/foreign-key check — so this loop waits through the migration window and
# won't declare a half-migrated or broken upgrade "ready". (60s comfortably exceeds
# the compose start_period; /readyz 503s until Core is genuinely ready.)
echo "▸ Waiting for backend to become ready (/readyz)..."
for i in $(seq 1 60); do
    if curl -sf --connect-timeout 1 --max-time 5 "http://localhost:${BACKEND_PORT}/readyz" > /dev/null 2>&1; then
        echo "  Backend ready."
        break
    fi
    if [ "$i" -eq 60 ]; then
        # A timed-out readiness wait is a FAILED update (mid-migration or broken DB),
        # not a cosmetic warning — exit non-zero so callers/automation see it.
        echo "  ERROR: Backend did not become ready within 60s."
        echo "  Diagnose: docker logs vedetta-backend  and  curl http://localhost:${BACKEND_PORT}/readyz"
        exit 1
    fi
    sleep 1
done

echo ""
echo "═══════════════════════════════════════════"
echo "  Core update complete."
echo "  Dashboard: http://localhost:${FRONTEND_PORT}"
echo "  API:       http://localhost:${BACKEND_PORT}/api/v1/status (read/admin bearer required)"
echo "═══════════════════════════════════════════"
