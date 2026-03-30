#!/usr/bin/env bash
#
# Vedetta Sensor — Install Script
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/vedetta-network/vedetta/main/sensor/deploy/install.sh | sudo bash -s -- --core http://<CORE_IP>:8080
#
# What it does:
#   1. Detects OS (macOS / Debian / Ubuntu / Alpine / RHEL / Fedora / Arch)
#   2. Installs nmap if missing
#   3. Installs Go if missing (needed to build from source)
#   4. Builds the sensor binary
#   5. Installs it as a persistent service (launchd on macOS, systemd on Linux)
#
set -euo pipefail

VEDETTA_VERSION="0.1.0-dev"
INSTALL_DIR="/usr/local/bin"
REPO_URL="https://github.com/vedetta-network/vedetta.git"
SENSOR_BIN="vedetta-sensor"
CORE_URL=""
SENSOR_FLAGS=""
SKIP_SERVICE=false
UNINSTALL=false

# On macOS, Homebrew and Go must not run as root.
# Capture the real (non-root) user so we can drop privileges for those commands.
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~${REAL_USER}")

# Run a command as the real (non-root) user
as_user() {
    if [[ "$(id -u)" -eq 0 && "$REAL_USER" != "root" ]]; then
        sudo -u "$REAL_USER" -- "$@"
    else
        "$@"
    fi
}

# --- Helpers ---

info()  { printf "\033[1;34m[vedetta]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[vedetta]\033[0m %s\n" "$*"; }
error() { printf "\033[1;31m[vedetta]\033[0m %s\n" "$*" >&2; }
die()   { error "$*"; exit 1; }

usage() {
    cat <<EOF
Vedetta Sensor Installer v${VEDETTA_VERSION}

Usage:
  sudo bash install.sh --core http://<CORE_IP>:8080 [OPTIONS]

Required:
  --core <url>        Vedetta Core API URL (e.g. http://10.0.0.5:8080)

Options:
  --cidr <cidr>       Override auto-detected subnet (e.g. 10.0.107.0/24)
  --interval <dur>    Scan interval (default: 5m)
  --ports             Enable top-100 port scanning
  --primary           Register as the primary sensor
  --no-service        Build and install binary only, skip service setup
  --uninstall         Remove sensor binary and service
  -h, --help          Show this help

Examples:
  # Basic install — auto-detect subnet, 5min scan cycle
  sudo bash install.sh --core http://10.0.0.5:8080

  # IoT-focused sensor with port scanning
  sudo bash install.sh --core http://10.0.0.5:8080 --cidr 10.0.107.0/24 --ports

  # Remote install via curl
  curl -fsSL https://raw.githubusercontent.com/vedetta-network/vedetta/main/sensor/deploy/install.sh | sudo bash -s -- --core http://10.0.0.5:8080
EOF
    exit 0
}

# --- Parse args ---

while [[ $# -gt 0 ]]; do
    case "$1" in
        --core)       CORE_URL="$2"; shift 2 ;;
        --cidr)       SENSOR_FLAGS="$SENSOR_FLAGS --cidr $2"; shift 2 ;;
        --interval)   SENSOR_FLAGS="$SENSOR_FLAGS --interval $2"; shift 2 ;;
        --ports)      SENSOR_FLAGS="$SENSOR_FLAGS --ports"; shift ;;
        --primary)    SENSOR_FLAGS="$SENSOR_FLAGS --primary"; shift ;;
        --no-service) SKIP_SERVICE=true; shift ;;
        --uninstall)  UNINSTALL=true; shift ;;
        -h|--help)    usage ;;
        *)            die "Unknown option: $1 (use --help for usage)" ;;
    esac
done

# --- Detect OS ---

detect_os() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Darwin) PLATFORM="macos" ;;
        Linux)  PLATFORM="linux" ;;
        *)      die "Unsupported OS: $OS" ;;
    esac

    # Detect Linux distro
    DISTRO="unknown"
    if [[ "$PLATFORM" == "linux" ]]; then
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
            DISTRO="${ID:-unknown}"
        elif [[ -f /etc/alpine-release ]]; then
            DISTRO="alpine"
        fi
    fi

    info "Detected: $PLATFORM ($DISTRO) $ARCH"
}

# --- Uninstall ---

do_uninstall() {
    info "Uninstalling Vedetta Sensor..."

    if [[ "$PLATFORM" == "macos" ]]; then
        if launchctl list | grep -q com.vedetta.sensor 2>/dev/null; then
            info "Stopping launchd service..."
            launchctl bootout system/com.vedetta.sensor 2>/dev/null || true
        fi
        rm -f /Library/LaunchDaemons/com.vedetta.sensor.plist
    else
        if systemctl is-active --quiet vedetta-sensor 2>/dev/null; then
            info "Stopping systemd service..."
            systemctl stop vedetta-sensor
        fi
        systemctl disable vedetta-sensor 2>/dev/null || true
        rm -f /etc/systemd/system/vedetta-sensor.service
        systemctl daemon-reload 2>/dev/null || true
    fi

    rm -f "${INSTALL_DIR}/${SENSOR_BIN}"
    info "Vedetta Sensor uninstalled."
    exit 0
}

# --- Install dependencies ---

install_nmap() {
    if command -v nmap &>/dev/null; then
        info "nmap found: $(command -v nmap)"
        return
    fi

    info "Installing nmap..."
    case "$PLATFORM" in
        macos)
            if as_user command -v brew &>/dev/null; then
                as_user brew install nmap
            else
                die "nmap not found. Install Homebrew (https://brew.sh) then run: brew install nmap"
            fi
            ;;
        linux)
            case "$DISTRO" in
                ubuntu|debian|pop|linuxmint)
                    apt-get update -qq && apt-get install -y -qq nmap ;;
                alpine)
                    apk add --no-cache nmap ;;
                fedora)
                    dnf install -y nmap ;;
                centos|rhel|rocky|almalinux)
                    yum install -y nmap ;;
                arch|manjaro)
                    pacman -S --noconfirm nmap ;;
                *)
                    die "Unsupported distro '$DISTRO'. Install nmap manually, then re-run this script." ;;
            esac
            ;;
    esac
    info "nmap installed."
}

install_go() {
    # Check both root and user PATH for Go
    if command -v go &>/dev/null; then
        info "Go found: $(go version)"
        return
    fi
    if as_user command -v go &>/dev/null; then
        info "Go found (user): $(as_user go version)"
        return
    fi

    info "Installing Go..."
    case "$PLATFORM" in
        macos)
            if as_user command -v brew &>/dev/null; then
                as_user brew install go
            else
                die "Go not found. Install Homebrew (https://brew.sh) then run: brew install go"
            fi
            ;;
        linux)
            # Install latest Go from official tarball
            GO_VERSION="1.22.5"
            GO_ARCH="$ARCH"
            [[ "$GO_ARCH" == "x86_64" ]] && GO_ARCH="amd64"
            [[ "$GO_ARCH" == "aarch64" ]] && GO_ARCH="arm64"

            GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
            info "Downloading Go ${GO_VERSION} for ${GO_ARCH}..."
            curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
            rm -rf /usr/local/go
            tar -C /usr/local -xzf "/tmp/${GO_TAR}"
            rm "/tmp/${GO_TAR}"
            export PATH="/usr/local/go/bin:$PATH"
            ;;
    esac
    info "Go installed."
}

# --- Build sensor ---

build_sensor() {
    # Create temp dir as the real user so git/go can write to it
    BUILD_TMP="$(as_user mktemp -d 2>/dev/null || mktemp -d)"
    chown -R "$REAL_USER" "$BUILD_TMP" 2>/dev/null || true

    info "Cloning Vedetta repo..."
    as_user git clone --depth 1 --quiet "$REPO_URL" "$BUILD_TMP/vedetta"

    info "Building sensor..."
    as_user bash -c "cd '$BUILD_TMP/vedetta/sensor' && go build -o '$BUILD_TMP/${SENSOR_BIN}' ./cmd/vedetta-sensor"

    info "Installing binary to ${INSTALL_DIR}/${SENSOR_BIN}"
    cp "$BUILD_TMP/${SENSOR_BIN}" "${INSTALL_DIR}/${SENSOR_BIN}"
    chmod +x "${INSTALL_DIR}/${SENSOR_BIN}"

    rm -rf "$BUILD_TMP"
    info "Sensor binary installed."
}

# --- Install service ---

install_service_macos() {
    PLIST="/Library/LaunchDaemons/com.vedetta.sensor.plist"
    LOG_DIR="/usr/local/var/log"
    mkdir -p "$LOG_DIR"

    info "Installing launchd service..."

    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vedetta.sensor</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${SENSOR_BIN}</string>
        <string>--core</string>
        <string>${CORE_URL}</string>
PLIST

    # Append any extra flags as individual array elements
    for flag in $SENSOR_FLAGS; do
        echo "        <string>${flag}</string>" >> "$PLIST"
    done

    cat >> "$PLIST" <<PLIST
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/vedetta-sensor.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/vedetta-sensor.log</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
PLIST

    # Stop existing service if running
    launchctl bootout system/com.vedetta.sensor 2>/dev/null || true

    # Load and start
    launchctl bootstrap system "$PLIST"

    info "Sensor service started (launchd)."
    info "Logs: tail -f ${LOG_DIR}/vedetta-sensor.log"
}

install_service_linux() {
    UNIT="/etc/systemd/system/vedetta-sensor.service"

    info "Installing systemd service..."

    cat > "$UNIT" <<UNIT
[Unit]
Description=Vedetta Network Sensor
Documentation=https://github.com/vedetta-network/vedetta
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${SENSOR_BIN} --core ${CORE_URL}${SENSOR_FLAGS:+ $SENSOR_FLAGS}
Restart=always
RestartSec=10
User=root

NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now vedetta-sensor

    info "Sensor service started (systemd)."
    info "Logs: journalctl -u vedetta-sensor -f"
}

# --- Main ---

main() {
    detect_os

    if [[ "$UNINSTALL" == true ]]; then
        do_uninstall
    fi

    if [[ -z "$CORE_URL" ]]; then
        die "Missing required --core <url>. Example: --core http://10.0.0.5:8080"
    fi

    # Check for root/sudo
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi

    info "Installing Vedetta Sensor v${VEDETTA_VERSION}"
    info "Core URL: ${CORE_URL}"

    install_nmap
    install_go
    build_sensor

    if [[ "$SKIP_SERVICE" == true ]]; then
        info "Skipping service install (--no-service)."
        info "Run manually: sudo ${INSTALL_DIR}/${SENSOR_BIN} --core ${CORE_URL}"
    else
        case "$PLATFORM" in
            macos) install_service_macos ;;
            linux) install_service_linux ;;
        esac
    fi

    echo ""
    info "Installation complete!"
    info "The sensor will auto-detect your subnet and begin scanning."
    info "Add additional networks via the Vedetta dashboard → Scan Targets."
    echo ""
}

main
