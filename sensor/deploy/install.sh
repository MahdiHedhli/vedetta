#!/bin/bash
#
# Vedetta Sensor Easy Installer
# For home users and small networks
#
# Usage:
#   curl -fsSL ... | bash -s -- --core http://192.168.1.50:8080
#   or
#   sudo ./install.sh --core http://192.168.1.50:8080
#

set -e

CORE_URL=""
RESET=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --core)
      CORE_URL="$2"
      shift 2
      ;;
    --reset)
      RESET=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ -z "$CORE_URL" ]; then
  echo "Usage: $0 --core http://YOUR-CORE-IP:8080 [--reset]"
  exit 1
fi

echo "==> Vedetta Sensor Installer"
echo "    Core: $CORE_URL"
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "==> Detected: $OS on $ARCH"

# Install dependencies
install_nmap() {
  if command -v nmap >/dev/null 2>&1; then
    echo "==> nmap is already installed"
    return
  fi

  echo "==> Installing nmap (required for active scanning)..."

  if [ "$OS" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      brew install nmap
    elif command -v port >/dev/null 2>&1; then
      sudo port install nmap
    else
      echo "Please install Homebrew or MacPorts, then run: brew install nmap"
      exit 1
    fi
  elif [ "$OS" = "Linux" ]; then
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -qq && sudo apt-get install -y nmap
    elif command -v dnf >/dev/null 2>&1; then
      sudo dnf install -y nmap
    elif command -v pacman >/dev/null 2>&1; then
      sudo pacman -S --noconfirm nmap
    else
      echo "Please install nmap manually for your distribution."
      exit 1
    fi
  fi
}

install_nmap

# Build the sensor
echo "==> Building vedetta-sensor (this may take a minute)..."
cd "$(dirname "$0")/../.."
go build -o /tmp/vedetta-sensor ./sensor/cmd/vedetta-sensor

echo "==> Installing binary to /usr/local/bin..."
sudo mkdir -p /usr/local/bin
sudo cp /tmp/vedetta-sensor /usr/local/bin/vedetta-sensor
sudo chmod +x /usr/local/bin/vedetta-sensor

# Handle token reset
if [ "$RESET" = true ]; then
  echo "==> Resetting sensor authentication..."
  sudo rm -f /root/.vedetta/sensor-token 2>/dev/null || true
  rm -f "$HOME/.vedetta/sensor-token" 2>/dev/null || true
fi

# Set up as a service
echo "==> Setting up as a background service..."

if [ "$OS" = "Darwin" ]; then
  # macOS - launchd
  PLIST="/Library/LaunchDaemons/com.vedetta.sensor.plist"
  sudo tee "$PLIST" > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vedetta.sensor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vedetta-sensor</string>
        <string>--core</string>
        <string>$CORE_URL</string>
        <string>--cidr</string>
        <string>auto</string>
        <string>--dns</string>
        <string>--passive-discovery</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/vedetta-sensor.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/vedetta-sensor.log</string>
</dict>
</plist>
EOF

  sudo launchctl unload "$PLIST" 2>/dev/null || true
  sudo launchctl load -w "$PLIST"
  echo "==> Sensor installed as a LaunchDaemon (will start on boot)"

else
  # Linux - systemd
  SERVICE="/etc/systemd/system/vedetta-sensor.service"
  sudo tee "$SERVICE" > /dev/null <<EOF
[Unit]
Description=Vedetta Sensor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vedetta-sensor --core $CORE_URL --cidr auto --dns --passive-discovery
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable vedetta-sensor
  sudo systemctl restart vedetta-sensor
  echo "==> Sensor installed as a systemd service"
fi

echo ""
echo "==> ✅ Installation complete!"
echo ""
echo "Sensor is now running and will start automatically on boot."
echo ""
echo "Useful commands:"
echo "  sudo systemctl status vedetta-sensor     # Linux"
echo "  sudo launchctl list | grep vedetta       # macOS"
echo "  sudo tail -f /var/log/vedetta-sensor.log"
echo ""
echo "To reset authentication in the future, run:"
echo "  sudo /usr/local/bin/vedetta-sensor --reset"
echo ""
echo "Dashboard: http://YOUR-CORE-IP:3107"
echo ""
