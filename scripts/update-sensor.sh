#!/usr/bin/env bash
#
# Vedetta — Update Sensor Only
#
# Usage:
#   sudo ./scripts/update-sensor.sh
#
# Pulls latest code, rebuilds the sensor binary, and restarts the service.
# Does NOT touch Core Docker containers.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REAL_USER="${SUDO_USER:-$USER}"

echo "═══════════════════════════════════════════"
echo "  Vedetta — Sensor Update"
echo "═══════════════════════════════════════════"
echo ""

cd "$PROJECT_DIR"

# --- Pull latest code ---
echo "▸ Pulling latest from git..."
sudo -u "$REAL_USER" git pull --rebase
echo ""

# --- Rebuild sensor ---
echo "▸ Building sensor..."
cd "$PROJECT_DIR/sensor"
sudo -u "$REAL_USER" go mod tidy
sudo -u "$REAL_USER" go build -o vedetta-sensor ./cmd/vedetta-sensor
echo ""

echo "▸ Installing binary..."
cp vedetta-sensor /usr/local/bin/vedetta-sensor
echo "  Installed to /usr/local/bin/vedetta-sensor"
echo ""

# --- Restart service ---
if [[ "$(uname)" == "Darwin" ]]; then
    if launchctl list 2>/dev/null | grep -q vedetta; then
        echo "▸ Restarting sensor (launchd)..."
        launchctl bootout system/com.vedetta.sensor 2>/dev/null || true
        launchctl bootstrap system /Library/LaunchDaemons/com.vedetta.sensor.plist
        echo "  Sensor restarted."
    else
        echo "  No launchd service found — start manually:"
        echo "    sudo vedetta-sensor --core http://localhost:8080"
    fi
elif command -v systemctl &> /dev/null; then
    if systemctl is-enabled vedetta-sensor &> /dev/null; then
        echo "▸ Restarting sensor (systemd)..."
        systemctl restart vedetta-sensor
        echo "  Sensor restarted."
    else
        echo "  No systemd service found — start manually:"
        echo "    sudo vedetta-sensor --core http://localhost:8080"
    fi
else
    echo "  No service manager detected — start manually:"
    echo "    sudo vedetta-sensor --core http://localhost:8080"
fi

# --- Verify ---
echo ""
echo "▸ Checking sensor version..."
vedetta-sensor --version 2>/dev/null || echo "  (binary not on PATH)"

echo ""
echo "═══════════════════════════════════════════"
echo "  Sensor update complete."
echo "═══════════════════════════════════════════"
