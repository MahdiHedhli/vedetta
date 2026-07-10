#!/usr/bin/env bash
#
# Vedetta Sensor installer.
#
# Prefers a checksummed prebuilt binary from the latest GitHub release; falls
# back to building from source (installing Go + libpcap) when no release asset is
# available for this OS/arch. Safe to pipe from curl.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/MahdiHedhli/vedetta/main/sensor/deploy/install.sh \
#     | sudo bash -s -- --core http://YOUR-CORE-IP:8080
#
#   sudo ./install.sh --core http://YOUR-CORE-IP:8080 [--enroll-code CODE]
#                     [--reset] [--no-service] [--build-from-source] [--ref TAG]
#
set -euo pipefail

REPO="MahdiHedhli/vedetta"
CORE_URL=""
ENROLL_CODE=""
RESET=false
INSTALL_SERVICE=true
FORCE_SOURCE="${VEDETTA_BUILD_FROM_SOURCE:-0}"
REF="${VEDETTA_REF:-main}"
# Install destination (overridable so the installer test can run without root).
BIN_DIR="${VEDETTA_BIN_DIR:-/usr/local/bin}"
BIN_DEST="${BIN_DIR}/vedetta-sensor"

die() { echo "ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --core)              CORE_URL="${2:-}"; shift 2 ;;
    --enroll-code)       ENROLL_CODE="${2:-}"; shift 2 ;;
    --ref)               REF="${2:-}"; shift 2 ;;
    --reset)             RESET=true; shift ;;
    --no-service)        INSTALL_SERVICE=false; shift ;;
    --build-from-source) FORCE_SOURCE=1; shift ;;
    -h|--help)           grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                   die "unknown option: $1" ;;
  esac
done

[ -n "$CORE_URL" ] || die "missing --core http://YOUR-CORE-IP:8080"

OS="$(uname -s)"
MACH="$(uname -m)"
case "$OS" in
  Linux)  GOOS=linux ;;
  Darwin) GOOS=darwin ;;
  *)      die "unsupported OS: $OS (Linux and macOS are supported)" ;;
esac
case "$MACH" in
  x86_64|amd64)  GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *)             die "unsupported architecture: $MACH" ;;
esac

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "run as root or install sudo"
  SUDO="sudo"
fi

echo "==> Vedetta Sensor installer"
echo "    Core:   $CORE_URL"
echo "    Target: ${GOOS}/${GOARCH}"

# ---------------------------------------------------------------------------
# Runtime dependency: nmap (active scanning).
# ---------------------------------------------------------------------------
pkg_install() {
  # pkg_install <apt-name> <dnf-name> <pacman-name> <brew-name>
  if [ "$OS" = "Darwin" ]; then
    command -v brew >/dev/null 2>&1 || die "Homebrew required on macOS: https://brew.sh"
    brew list "$4" >/dev/null 2>&1 || brew install "$4"
  elif command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq && $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$1"
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y "$2"
  elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -S --noconfirm "$3"
  else
    die "no supported package manager found; install '$1' manually"
  fi
}

ensure_nmap() {
  command -v nmap >/dev/null 2>&1 && return
  echo "==> installing nmap"
  pkg_install nmap nmap nmap nmap
}

# ---------------------------------------------------------------------------
# Path 1: prebuilt binary from the latest release, checksum-verified.
# ---------------------------------------------------------------------------
BINARY=""
try_prebuilt() {
  command -v curl >/dev/null 2>&1 || return 1
  local tag base asset tmp sums
  tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
         | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | cut -d'"' -f4)"
  [ -n "$tag" ] || return 1
  base="https://github.com/${REPO}/releases/download/${tag}"
  asset="vedetta-sensor_${GOOS}_${GOARCH}.tar.gz"
  tmp="$(mktemp -d)"
  echo "==> downloading prebuilt ${asset} (${tag})"
  curl -fsSL -o "${tmp}/${asset}" "${base}/${asset}" || { rm -rf "$tmp"; return 1; }
  curl -fsSL -o "${tmp}/checksums.txt" "${base}/checksums.txt" || { rm -rf "$tmp"; return 1; }
  echo "==> verifying checksum"
  sums="sha256sum"; command -v sha256sum >/dev/null 2>&1 || sums="shasum -a 256"
  ( cd "$tmp" && grep " ${asset}\$" checksums.txt | $sums -c - ) || { echo "!! checksum FAILED"; rm -rf "$tmp"; return 1; }
  tar -xzf "${tmp}/${asset}" -C "$tmp"
  [ -f "${tmp}/vedetta-sensor" ] || { rm -rf "$tmp"; return 1; }
  BINARY="${tmp}/vedetta-sensor"
}

# ---------------------------------------------------------------------------
# Path 2: build from source (installs Go + libpcap as needed).
# ---------------------------------------------------------------------------
ensure_go() {
  if command -v go >/dev/null 2>&1; then return; fi
  echo "==> installing Go (latest stable)"
  if [ "$OS" = "Darwin" ]; then
    pkg_install go golang go go
    return
  fi
  local ver tgz tmp
  ver="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
  [ -n "$ver" ] || die "could not resolve latest Go version"
  tmp="$(mktemp -d)"; tgz="${tmp}/go.tgz"
  curl -fsSL -o "$tgz" "https://go.dev/dl/${ver}.${GOOS}-${GOARCH}.tar.gz" || die "Go download failed"
  $SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf "$tgz"
  export PATH="/usr/local/go/bin:${PATH}"
}

build_from_source() {
  command -v git >/dev/null 2>&1 || pkg_install git git git git
  if [ "$OS" = "Linux" ]; then
    echo "==> installing libpcap headers"
    pkg_install libpcap-dev libpcap-devel libpcap libpcap  # macOS ships libpcap
  fi
  ensure_go
  local src
  src="$(mktemp -d)"
  echo "==> cloning ${REPO}@${REF}"
  git clone --depth 1 --branch "$REF" "https://github.com/${REPO}" "${src}/vedetta" >/dev/null 2>&1 \
    || git clone --depth 1 "https://github.com/${REPO}" "${src}/vedetta" >/dev/null 2>&1 \
    || die "git clone failed"
  echo "==> building vedetta-sensor (CGO)"
  ( cd "${src}/vedetta/sensor" && CGO_ENABLED=1 go build -o "${src}/vedetta-sensor" ./cmd/vedetta-sensor )
  BINARY="${src}/vedetta-sensor"
}

# ---------------------------------------------------------------------------
# Install.
# ---------------------------------------------------------------------------
ensure_nmap

if [ -n "${VEDETTA_SENSOR_BINARY:-}" ]; then
  # Escape hatch (also used by the installer test): use a caller-supplied binary
  # instead of downloading or building one.
  BINARY="$VEDETTA_SENSOR_BINARY"
  echo "==> using caller-supplied binary: $BINARY"
elif [ "$FORCE_SOURCE" != "1" ] && try_prebuilt; then
  echo "==> using checksum-verified prebuilt binary"
else
  [ "$FORCE_SOURCE" = "1" ] || echo "==> no prebuilt release asset for ${GOOS}/${GOARCH}; building from source"
  build_from_source
fi

echo "==> installing to ${BIN_DEST}"
$SUDO install -d "$BIN_DIR"
$SUDO install -m 0755 "$BINARY" "$BIN_DEST"
"$BIN_DEST" --version

if [ "$RESET" = true ]; then
  echo "==> resetting sensor authentication"
  $SUDO "$BIN_DEST" --reset || true
fi

if [ "$INSTALL_SERVICE" != true ]; then
  echo ""
  echo "==> ✅ binary installed (service skipped: --no-service)"
  echo "    run it with: sudo vedetta-sensor --core $CORE_URL${ENROLL_CODE:+ --enroll-code $ENROLL_CODE}"
  exit 0
fi

echo "==> configuring service"
EXTRA=""
[ -n "$ENROLL_CODE" ] && EXTRA=" --enroll-code $ENROLL_CODE"

if [ "$OS" = "Darwin" ]; then
  PLIST="${VEDETTA_PLIST_PATH:-/Library/LaunchDaemons/com.vedetta.sensor.plist}"
  # Enrollment code must reach the LaunchDaemon's ProgramArguments for the
  # INITIAL registration — otherwise a macOS service ignores a supplied code
  # (issue #35). Each flag is its own <string> element in the array.
  ENROLL_ARGS=""
  [ -n "$ENROLL_CODE" ] && ENROLL_ARGS="    <string>--enroll-code</string><string>${ENROLL_CODE}</string>"
  $SUDO tee "$PLIST" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.vedetta.sensor</string>
  <key>ProgramArguments</key><array>
    <string>${BIN_DEST}</string>
    <string>--core</string><string>${CORE_URL}</string>
    <string>--cidr</string><string>auto</string>
    <string>--dns</string>
    <string>--passive-discovery</string>
${ENROLL_ARGS}
  </array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/vedetta-sensor.log</string>
  <key>StandardErrorPath</key><string>/var/log/vedetta-sensor.log</string>
</dict></plist>
EOF
  $SUDO launchctl unload "$PLIST" 2>/dev/null || true
  $SUDO launchctl load -w "$PLIST"
  echo "==> installed as a LaunchDaemon"
  if [ -n "$ENROLL_CODE" ]; then
    echo ""
    echo "    NOTE: the enrollment code is single-use. After the sensor's first"
    echo "    successful registration it persists a token and no longer needs the"
    echo "    code. Remove it from the LaunchDaemon so a KeepAlive restart does not"
    echo "    replay a now-consumed code — re-run this installer WITHOUT --enroll-code:"
    echo "      sudo ./install.sh --core $CORE_URL"
    echo "    (or edit $PLIST, delete the two --enroll-code ProgramArguments <string>"
    echo "    lines, then: sudo launchctl unload $PLIST && sudo launchctl load -w $PLIST)"
  fi
else
  SERVICE="${VEDETTA_SERVICE_PATH:-/etc/systemd/system/vedetta-sensor.service}"
  $SUDO tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=Vedetta Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DEST} --core ${CORE_URL} --cidr auto --dns --passive-discovery${EXTRA}
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable vedetta-sensor
  $SUDO systemctl restart vedetta-sensor
  echo "==> installed as a systemd service"
fi

echo ""
echo "==> ✅ Installation complete"
echo "    Logs:   sudo tail -f /var/log/vedetta-sensor.log   (or: journalctl -u vedetta-sensor -f)"
echo "    Reset:  sudo vedetta-sensor --reset"
