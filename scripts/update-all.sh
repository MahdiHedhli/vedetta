#!/usr/bin/env bash
#
# Vedetta — Update Everything (Core + Sensor)
#
# Usage:
#   sudo ./scripts/update-all.sh
#
# Pulls latest code, rebuilds Docker images, restarts Core services,
# rebuilds the sensor binary, and restarts the sensor service.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REAL_USER="${SUDO_USER:-$USER}"

echo "═══════════════════════════════════════════"
echo "  Vedetta — Full Update"
echo "═══════════════════════════════════════════"
echo ""

# --- Pull latest code ---
echo "▸ Pulling latest from git..."
cd "$PROJECT_DIR"
sudo -u "$REAL_USER" git pull --rebase
echo ""

# --- Update Core ---
echo "▸ Rebuilding Core Docker images..."
docker compose down
docker compose build --no-cache backend frontend
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

# --- Update Sensor ---
echo "▸ Rebuilding sensor..."
cd "$PROJECT_DIR/sensor"
sudo -u "$REAL_USER" go mod tidy
sudo -u "$REAL_USER" go build -o vedetta-sensor ./cmd/vedetta-sensor
cp vedetta-sensor /usr/local/bin/vedetta-sensor
echo "  Binary installed to /usr/local/bin/vedetta-sensor"
echo ""

# Restart sensor service
if [[ "$(uname)" == "Darwin" ]]; then
    if launchctl list 2>/dev/null | grep -q vedetta; then
        echo "▸ Restarting sensor (launchd)..."
        launchctl bootout system/com.vedetta.sensor 2>/dev/null || true
        launchctl bootstrap system /Library/LaunchDaemons/com.vedetta.sensor.plist
        echo "  Sensor restarted."
    else
        echo "  No launchd service found — start manually: sudo vedetta-sensor --core http://localhost:8080"
    fi
elif command -v systemctl &> /dev/null; then
    if systemctl is-enabled vedetta-sensor &> /dev/null; then
        echo "▸ Restarting sensor (systemd)..."
        systemctl restart vedetta-sensor
        echo "  Sensor restarted."
    else
        echo "  No systemd service found — start manually: sudo vedetta-sensor --core http://localhost:8080"
    fi
fi

echo ""
echo "═══════════════════════════════════════════"
echo "  Update complete."
echo "  Dashboard: http://localhost:3107"
echo "  API:       http://localhost:8080/api/v1/status"
echo "═══════════════════════════════════════════"
