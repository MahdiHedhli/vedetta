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
PLIST_SRC="$PROJECT_DIR/sensor/deploy/com.vedetta.sensor.plist"
PLIST_DEST="/Library/LaunchDaemons/com.vedetta.sensor.plist"
SERVICE_ID="system/com.vedetta.sensor"
SENSOR_BIN="/usr/local/bin/vedetta-sensor"
CORE_URL="${VEDETTA_CORE_URL:-http://localhost:8080}"
LOG_FILE="/usr/local/var/log/vedetta-sensor.log"
MAX_RETRIES=3
VERIFY_WAIT=5

# ─── Sensor management ────────────────────────────────────────

stop_sensor() {
    if [[ "$(uname)" == "Darwin" ]]; then
        launchctl bootout "$SERVICE_ID" 2>/dev/null || true
    elif command -v systemctl &> /dev/null; then
        systemctl stop vedetta-sensor 2>/dev/null || true
    fi

    sleep 1
    if pgrep -f vedetta-sensor > /dev/null 2>&1; then
        echo "  Sensor still running — sending SIGTERM..."
        pkill -f vedetta-sensor 2>/dev/null || true
        sleep 2
        if pgrep -f vedetta-sensor > /dev/null 2>&1; then
            echo "  Forcing shutdown (SIGKILL)..."
            pkill -9 -f vedetta-sensor 2>/dev/null || true
            sleep 1
        fi
    fi
}

install_sensor_service() {
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "  Installing launchd service..."
        mkdir -p "$(dirname "$LOG_FILE")"

        sed "s|http://CORE_IP:8080|${CORE_URL}|g" "$PLIST_SRC" > "$PLIST_DEST"
        chown root:wheel "$PLIST_DEST"
        chmod 644 "$PLIST_DEST"

        launchctl bootout "$SERVICE_ID" 2>/dev/null || true
        sleep 1
        if launchctl bootstrap system "$PLIST_DEST"; then
            echo "  ✓ Sensor installed as launchd service (survives reboots)."
            return 0
        else
            echo "  ✗ launchd bootstrap failed."
            return 1
        fi
    elif command -v systemctl &> /dev/null; then
        echo "  Installing systemd service..."
        local unit_src="$PROJECT_DIR/sensor/deploy/vedetta-sensor.service"
        if [[ -f "$unit_src" ]]; then
            cp "$unit_src" /etc/systemd/system/vedetta-sensor.service
            systemctl daemon-reload
            systemctl enable --now vedetta-sensor
            echo "  ✓ Sensor installed as systemd service (survives reboots)."
            return 0
        else
            echo "  ✗ No systemd unit file found at $unit_src"
            return 1
        fi
    fi
    return 1
}

start_sensor_once() {
    echo "  Launching sensor (this session only)..."
    mkdir -p "$(dirname "$LOG_FILE")"
    nohup "$SENSOR_BIN" --core "$CORE_URL" >> "$LOG_FILE" 2>&1 &
    local pid=$!
    echo "  ✓ Sensor launched (PID $pid)"
    echo "  Logs: $LOG_FILE"
}

prompt_sensor_start() {
    echo ""
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │  How would you like to start the sensor? │"
    echo "  ├─────────────────────────────────────────┤"
    echo "  │  1) Launch now (stops on reboot)        │"
    echo "  │  2) Install as service (survives reboot)│"
    echo "  │  3) Skip — I'll start it manually       │"
    echo "  └─────────────────────────────────────────┘"
    echo ""

    local choice
    while true; do
        read -rp "  Select [1/2/3] (default: 2): " choice
        choice="${choice:-2}"
        case "$choice" in
            1)
                start_sensor_once
                return
                ;;
            2)
                if install_sensor_service; then
                    return
                else
                    echo ""
                    echo "  Service installation failed. Falling back to direct launch..."
                    start_sensor_once
                    return
                fi
                ;;
            3)
                echo "  Skipped. To start manually:"
                echo "    sudo $SENSOR_BIN --core $CORE_URL"
                return
                ;;
            *)
                echo "  Please enter 1, 2, or 3."
                ;;
        esac
    done
}

restart_sensor() {
    echo "▸ Restarting sensor..."
    stop_sensor

    if [[ "$(uname)" == "Darwin" ]]; then
        restart_sensor_launchd
    elif command -v systemctl &> /dev/null; then
        restart_sensor_systemd
    else
        echo "  No service manager detected."
        prompt_sensor_start
        verify_sensor
        return
    fi

    verify_sensor
}

restart_sensor_launchd() {
    if [[ ! -f "$PLIST_DEST" ]]; then
        echo "  No sensor service is currently installed."
        prompt_sensor_start
        return
    fi

    for attempt in $(seq 1 $MAX_RETRIES); do
        echo "  launchd bootstrap attempt $attempt/$MAX_RETRIES..."
        if launchctl bootstrap system "$PLIST_DEST" 2>/dev/null; then
            echo "  ✓ launchd bootstrap succeeded."
            return
        fi

        echo "  Bootstrap failed — unloading and retrying..."
        launchctl bootout "$SERVICE_ID" 2>/dev/null || true
        sleep 1
    done

    echo ""
    echo "  launchd failed after $MAX_RETRIES attempts."
    prompt_sensor_start
}

restart_sensor_systemd() {
    if ! systemctl is-enabled vedetta-sensor &> /dev/null; then
        echo "  No sensor service is currently installed."
        prompt_sensor_start
        return
    fi

    for attempt in $(seq 1 $MAX_RETRIES); do
        echo "  systemd restart attempt $attempt/$MAX_RETRIES..."
        if systemctl restart vedetta-sensor 2>/dev/null; then
            sleep 1
            if systemctl is-active --quiet vedetta-sensor; then
                echo "  ✓ systemd restart succeeded."
                return
            fi
        fi
        sleep 2
    done

    echo ""
    echo "  systemd failed after $MAX_RETRIES attempts."
    prompt_sensor_start
}

verify_sensor() {
    echo ""
    echo "▸ Verifying sensor is running..."
    sleep "$VERIFY_WAIT"
    if pgrep -f vedetta-sensor > /dev/null 2>&1; then
        local pid
        pid=$(pgrep -f vedetta-sensor | head -1)
        echo "  ✓ Sensor running (PID $pid)"
    else
        echo "  ✗ Sensor does not appear to be running."
        echo ""
        echo "  This can happen if the sensor exited immediately on startup."
        echo "  Check logs: $LOG_FILE"
        echo "  Manual start: sudo $SENSOR_BIN --core $CORE_URL"
    fi
}

# ─── Main ──────────────────────────────────────────────────────

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
cp vedetta-sensor "$SENSOR_BIN"
echo "  Installed to $SENSOR_BIN"
echo ""

# --- Restart with resilience ---
restart_sensor

echo ""
echo "═══════════════════════════════════════════"
echo "  Sensor update complete."
echo "  Dashboard: http://localhost:3107"
echo "═══════════════════════════════════════════"
