#!/usr/bin/env bash
#
# Vedetta Sensor installer.
#
# On Linux, prefers a checksummed prebuilt binary from the latest GitHub release
# and falls back to building from source (installing Go + libpcap) when no asset
# matches this arch. On macOS there is no prebuilt Darwin release asset, so the
# sensor is always built from source (Go via go.dev; macOS ships libpcap).
# Homebrew, when needed for nmap, is run as the invoking user — never as root.
# Safe to pipe from curl.
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

# Fixed, root-only token location shared by the one-shot enrollment step and the
# long-running service, so both agree regardless of $HOME/sudo resolution. Overridable
# via VEDETTA_SENSOR_TOKEN_FILE (also honoured by the sensor binary; used by the tests).
if [ -n "${VEDETTA_SENSOR_TOKEN_FILE:-}" ]; then
  TOKEN_FILE="$VEDETTA_SENSOR_TOKEN_FILE"
elif [ "$OS" = "Darwin" ]; then
  TOKEN_FILE="/Library/Application Support/Vedetta/sensor-token"
else
  TOKEN_FILE="/var/lib/vedetta/sensor-token"
fi
TOKEN_DIR="$(dirname "$TOKEN_FILE")"

echo "==> Vedetta Sensor installer"
echo "    Core:   $CORE_URL"
echo "    Target: ${GOOS}/${GOARCH}"

# ---------------------------------------------------------------------------
# Runtime dependency: nmap (active scanning).
# ---------------------------------------------------------------------------
# Locate the Homebrew binary even when running under sudo: root's PATH usually
# omits /opt/homebrew/bin (Apple Silicon) and /usr/local/bin (Intel) where brew
# lives, so `command -v brew` alone fails after `sudo`.
find_brew() {
  local b
  b="$(command -v brew 2>/dev/null)" && { echo "$b"; return 0; }
  for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    [ -x "$b" ] && { echo "$b"; return 0; }
  done
  return 1
}

# Run Homebrew SAFELY. Homebrew refuses to run as root and doing so is unsafe,
# but this installer normally runs under sudo. Invoke brew as the original
# non-root user ($SUDO_USER); never as root (issue #45).
brew_run() {
  local brew_bin
  brew_bin="$(find_brew)" || die "Homebrew is required on macOS but 'brew' was not found. Install it from https://brew.sh (or pre-install the dependency), then re-run."
  if [ "$(id -u)" -ne 0 ]; then
    "$brew_bin" "$@"
    return
  fi
  local brew_user="${SUDO_USER:-}"
  if [ -z "$brew_user" ] || [ "$brew_user" = "root" ]; then
    die "Refusing to run Homebrew as root (brew forbids it). Re-run this installer with sudo from your normal account — e.g. 'sudo bash install.sh --core ...' so \$SUDO_USER is set — or pre-install the dependency yourself: brew install <pkg>."
  fi
  sudo -u "$brew_user" "$brew_bin" "$@"
}

pkg_install() {
  # pkg_install <apt-name> <dnf-name> <pacman-name> <brew-name>
  if [ "$OS" = "Darwin" ]; then
    brew_run list "$4" >/dev/null 2>&1 || brew_run install "$4"
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

# The DAEMON runs under the service manager's PATH, not the installer's. launchd hands
# a minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin) that EXCLUDES the Homebrew bin dir
# where `brew install nmap` lands (/opt/homebrew/bin on Apple Silicon, /usr/local/bin
# on Intel) — so nmap can be present for the installer yet invisible to the daemon,
# which then hits `log.Fatalf("device scanner unavailable")` and crash-loops. We
# compute the exact PATH the service will run with ONCE, verify dependencies against
# it, AND bake it into the plist/unit so "what we verify" and "what the daemon uses"
# are identical. SIP forbids symlinking nmap into the default dirs, so baking PATH is
# the only durable fix.
brew_bin_dir() {
  local b; b="$(find_brew)" || return 0
  dirname "$b"
}
daemon_path() {
  # Explicit override for non-standard layouts (and deterministic tests).
  if [ -n "${VEDETTA_DAEMON_PATH:-}" ]; then printf '%s' "$VEDETTA_DAEMON_PATH"; return; fi
  local bd raw; bd="$(brew_bin_dir)"
  if [ "$OS" = "Darwin" ]; then
    raw="${bd:+$bd:}/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  else
    # systemd's compiled-in default PATH, plus any Homebrew-on-Linux prefix.
    raw="${bd:+$bd:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  fi
  # Drop duplicate entries (brew_bin_dir may overlap the hardcoded fallback),
  # preserving first-seen order.
  printf '%s' "$raw" | awk -v RS=: -v ORS= '!seen[$0]++{ if(n++) printf ":"; printf "%s", $0 }'
}

# Is <cmd> resolvable from the DAEMON's PATH (not the installer's richer PATH)?
require_daemon_dep() { PATH="$DAEMON_PATH" command -v "$1" >/dev/null 2>&1; }

ensure_nmap() {
  require_daemon_dep nmap && return
  echo "==> installing nmap"
  pkg_install nmap nmap nmap nmap
  require_daemon_dep nmap || die \
"nmap is not resolvable from the service PATH:
    ${DAEMON_PATH}
The installer's shell sees: $(command -v nmap 2>/dev/null || echo '<none>').
Install nmap into a service-visible dir (macOS: brew install nmap; Linux: sudo apt-get install -y nmap / dnf install -y nmap / pacman -S nmap) and re-run."
}

# The sensor is CGO-linked to libpcap (gopacket). macOS ships libpcap in the base OS,
# but a Linux PREBUILT/caller-supplied binary needs the libpcap RUNTIME package or it
# fails cryptically in ld.so before main() (build-from-source only pulls the -dev
# headers). Install the runtime lib in EVERY Linux path, not just source builds.
ensure_libpcap_runtime() {
  [ "$OS" = "Linux" ] || return 0
  ldconfig -p 2>/dev/null | grep -q 'libpcap\.so' && return 0
  echo "==> installing libpcap runtime"
  pkg_install libpcap0.8 libpcap libpcap libpcap
}

# Post-install health gate: confirm the daemon actually STAYS UP before reporting
# success — the check the installer never had, which let an 18x crash-loop report
# "Installation complete". launchd has no restart counter, so on macOS we watch the log
# for the readiness marker ("Device scanner ready") and bail on the fatal marker
# ("device scanner unavailable"); systemd exposes NRestarts, so on Linux we watch
# is-active + a climbing restart count. Returns 0 healthy, 1 not. Tests that have no
# real service manager set VEDETTA_SKIP_HEALTHCHECK=1.
health_check() {
  [ "${VEDETTA_SKIP_HEALTHCHECK:-0}" = "1" ] && return 0
  local log="/var/log/vedetta-sensor.log" deadline=$((SECONDS + 25))
  if [ "$OS" = "Darwin" ]; then
    while [ "$SECONDS" -lt "$deadline" ]; do
      $SUDO grep -q 'device scanner unavailable' "$log" 2>/dev/null && return 1
      if $SUDO grep -q 'Device scanner ready' "$log" 2>/dev/null; then
        # "Device scanner ready" is logged BEFORE client.New (which can still
        # log.Fatalf), so it alone doesn't prove the daemon stays up. Settle, then
        # confirm no crash marker appeared AND launchd still shows it running.
        sleep 4
        $SUDO grep -q 'device scanner unavailable' "$log" 2>/dev/null && return 1
        $SUDO launchctl print system/com.vedetta.sensor 2>/dev/null | grep -qE 'state = running' && return 0
        return 1
      fi
      sleep 2
    done
    $SUDO launchctl print system/com.vedetta.sensor 2>/dev/null | grep -qE 'state = running' && return 0
    return 1
  fi
  local n0 n1 active
  n0="$($SUDO systemctl show -p NRestarts --value vedetta-sensor 2>/dev/null)"
  sleep 20
  active="$($SUDO systemctl is-active vedetta-sensor 2>/dev/null)"
  n1="$($SUDO systemctl show -p NRestarts --value vedetta-sensor 2>/dev/null)"
  [ "$active" = "active" ] && [ "${n1:-0}" -le "${n0:-0}" ] && return 0
  return 1
}

# ---------------------------------------------------------------------------
# Path 1: prebuilt binary from the latest release, checksum-verified.
# ---------------------------------------------------------------------------
BINARY=""
try_prebuilt() {
  command -v curl >/dev/null 2>&1 || return 1
  local base asset tmp sums url
  asset="vedetta-sensor_${GOOS}_${GOARCH}.tar.gz"
  if [ -n "${VEDETTA_RELEASE_TAG:-}" ]; then
    # Explicit pin (mirrors install.ps1 -Tag).
    base="https://github.com/${REPO}/releases/download/${VEDETTA_RELEASE_TAG}"
  else
    # Resolve the newest release that ships this asset. NOT /releases/latest — GitHub
    # defines "latest" as the newest NON-prerelease, so a beta published (correctly) as a
    # prerelease 404s there and the install would silently fall back to compiling mutable
    # main. /releases lists every published release newest-first (drafts are not returned
    # unauthenticated; prereleases are), so the first asset download URL matching our
    # platform is the newest published (pre)release's binary. Override with VEDETTA_RELEASE_TAG.
    url="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" 2>/dev/null \
           | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
           | cut -d'"' -f4 | grep "/${asset}\$" | head -1)"
    [ -n "$url" ] || return 1
    base="${url%/*}" # strip the filename → the release's download base (carries the tag)
  fi
  tmp="$(mktemp -d)"
  echo "==> downloading prebuilt ${asset} (${base##*/download/})"
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
  # Use the official go.dev tarball for BOTH Linux and macOS. On macOS this
  # deliberately avoids Homebrew so the toolchain install never depends on brew
  # (which cannot run as root — see issue #45); go.dev ships darwin-arm64 and
  # darwin-amd64 builds too.
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
# The PATH the service manager will hand the daemon; dependencies are verified against
# THIS (not the installer's richer PATH) and baked into the plist/unit below.
DAEMON_PATH="$(daemon_path)"
ensure_nmap
ensure_libpcap_runtime

if [ -n "${VEDETTA_SENSOR_BINARY:-}" ]; then
  # Escape hatch (also used by the installer test): use a caller-supplied binary
  # instead of downloading or building one.
  BINARY="$VEDETTA_SENSOR_BINARY"
  echo "==> using caller-supplied binary: $BINARY"
elif [ -n "${VEDETTA_RELEASE_TAG:-}" ] && [ "$FORCE_SOURCE" != "1" ]; then
  # Explicit release pin: install ONLY that pinned, checksum-verified asset. Fail
  # closed — never silently fall back to building mutable main when a pinned download
  # or checksum verification fails.
  try_prebuilt || die "pinned release ${VEDETTA_RELEASE_TAG}: asset download or checksum verification failed; refusing to fall back to a source build of main"
  echo "==> using checksum-verified prebuilt binary (${VEDETTA_RELEASE_TAG})"
elif [ "$OS" = "Darwin" ] && [ "$FORCE_SOURCE" != "1" ]; then
  # No prebuilt Darwin release asset is published, so don't probe the releases
  # API for one — build macOS from source directly (issue #45). macOS ships
  # libpcap; this installs Go (via go.dev, not brew) and compiles the sensor.
  echo "==> macOS: building the sensor from source (no prebuilt Darwin release asset)"
  build_from_source
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
# The installed binary is CGO-linked to libpcap; verify the runtime object actually
# resolves before building a service around it (Linux only; macOS ships libpcap).
if [ "$OS" = "Linux" ] && command -v ldd >/dev/null 2>&1; then
  ldd "$BIN_DEST" 2>/dev/null | grep -qi 'pcap.*not found' \
    && die "libpcap runtime is missing (the sensor is dynamically linked to it). Install it — Debian/Ubuntu: sudo apt-get install -y libpcap0.8 ; RHEL/Fedora: sudo dnf install -y libpcap ; Arch: sudo pacman -S libpcap — then re-run."
fi

# Guards (before any destructive/enrollment step) so a reset or a code-less fresh
# install can't strand the sensor — mirrors install.ps1.
if [ "$RESET" = true ] && [ -z "$ENROLL_CODE" ]; then
  die "--reset clears the sensor's auth token. Also pass --enroll-code <bound reset code> so it can re-enroll (an admin mints one via POST /api/v1/enrollment-codes). Refusing to strand the sensor."
fi
if [ "$INSTALL_SERVICE" = true ] && [ -z "$ENROLL_CODE" ] && [ ! -f "$TOKEN_FILE" ]; then
  die "no --enroll-code and no existing token at $TOKEN_FILE. A new sensor needs a one-time enrollment code to register. Mint one in the dashboard 'Connect a sensor' step and pass --enroll-code <CODE>."
fi

if [ "$RESET" = true ]; then
  echo "==> resetting sensor authentication"
  $SUDO env VEDETTA_SENSOR_TOKEN_FILE="$TOKEN_FILE" "$BIN_DEST" --reset || true
fi

# Enroll BEFORE creating the service, so the single-use code is spent in this one-shot
# step (supplied via the ENVIRONMENT, never on a command line or in the launchd/systemd
# service config where a local user could read it). The token persists to the fixed
# TOKEN_FILE the service also reads (set in the unit below), so there is no $HOME/sudo
# ambiguity between enrollment and the running service.
if [ -n "$ENROLL_CODE" ]; then
  echo "==> enrolling with Core (one-time code, kept out of the service configuration)"
  $SUDO install -d -m 0700 "$TOKEN_DIR"
  export VEDETTA_ENROLL_CODE="$ENROLL_CODE"
  ${SUDO:+$SUDO -E} env VEDETTA_SENSOR_TOKEN_FILE="$TOKEN_FILE" "$BIN_DEST" --enroll-only --core "$CORE_URL" --cidr auto \
    || die "enrollment failed (check --core, the enrollment code, and connectivity)"
  unset VEDETTA_ENROLL_CODE
fi

if [ "$INSTALL_SERVICE" != true ]; then
  echo ""
  echo "==> ✅ binary installed${ENROLL_CODE:+ and enrolled} (service skipped: --no-service)"
  echo "    run it with: sudo env VEDETTA_SENSOR_TOKEN_FILE='$TOKEN_FILE' vedetta-sensor --core $CORE_URL --cidr auto --dns"
  exit 0
fi

# Preflight: reproduce the SERVICE's exact environment (its PATH + the token file) and
# run the binary's own --check, so a dependency the daemon can't see (e.g. Homebrew
# nmap off launchd's minimal PATH) fails the install LOUDLY here instead of after a
# false "installed" and a silent crash-loop.
echo "==> preflight: verifying dependencies as the service will see them"
if ! ${SUDO:+$SUDO }env -i PATH="$DAEMON_PATH" VEDETTA_SENSOR_TOKEN_FILE="$TOKEN_FILE" "$BIN_DEST" --check --core "$CORE_URL"; then
  die "preflight failed — the service environment (PATH=$DAEMON_PATH) is missing a required dependency (see the FAIL line above). Fix it and re-run; refusing to write a service that would crash-loop."
fi

echo "==> configuring service"
# The enrollment code is intentionally NOT placed in the service definition — it was
# already spent in the one-shot enrollment step above and the token is persisted. The
# service authenticates with that token (VEDETTA_SENSOR_TOKEN_FILE), so a local user
# reading the launchd/systemd config learns nothing secret (issue #35).

if [ "$OS" = "Darwin" ]; then
  PLIST="${VEDETTA_PLIST_PATH:-/Library/LaunchDaemons/com.vedetta.sensor.plist}"
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
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>${DAEMON_PATH}</string>
    <key>VEDETTA_SENSOR_TOKEN_FILE</key><string>${TOKEN_FILE}</string>
  </dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/vedetta-sensor.log</string>
  <key>StandardErrorPath</key><string>/var/log/vedetta-sensor.log</string>
</dict></plist>
EOF
  $SUDO launchctl unload "$PLIST" 2>/dev/null || true
  # Start from a clean log so the post-install health check reads only THIS run's
  # markers. launchd opens the log append-mode, so a stale 'ready'/'unavailable' from a
  # prior run would otherwise decide the verdict — a false pass, or a false fail on the
  # documented repair re-run. Safe: the old daemon was just unloaded (no writer holds it).
  $SUDO sh -c ': > /var/log/vedetta-sensor.log' 2>/dev/null || true
  $SUDO launchctl load -w "$PLIST"
  echo "==> installed as a LaunchDaemon"
else
  SERVICE="${VEDETTA_SERVICE_PATH:-/etc/systemd/system/vedetta-sensor.service}"
  $SUDO tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=Vedetta Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PATH=${DAEMON_PATH}
Environment="VEDETTA_SENSOR_TOKEN_FILE=${TOKEN_FILE}"
ExecStartPre=/usr/bin/env sh -c 'command -v nmap >/dev/null 2>&1 || { echo "nmap not on service PATH: \$PATH" >&2; exit 1; }'
ExecStart=${BIN_DEST} --core ${CORE_URL} --cidr auto --dns --passive-discovery
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
echo "==> waiting for the sensor to come up..."
if health_check; then
  echo "==> ✅ Installation complete — sensor is up and healthy"
  echo "    Logs:   sudo tail -f /var/log/vedetta-sensor.log   (or: journalctl -u vedetta-sensor -f)"
  echo "    Reset:  sudo vedetta-sensor --reset"
else
  echo "" >&2
  echo "!! The sensor was installed but did NOT reach a healthy state (it may be crash-looping)." >&2
  if [ "$OS" = "Darwin" ]; then
    $SUDO tail -n 40 /var/log/vedetta-sensor.log 2>/dev/null >&2 || true
    if $SUDO grep -q 'device scanner unavailable' /var/log/vedetta-sensor.log 2>/dev/null; then
      echo "   Cause: nmap is not resolvable from the service PATH (${DAEMON_PATH})." >&2
      echo "   Fix:   brew install nmap, then re-run this installer with --core $CORE_URL to repair it." >&2
    fi
  else
    $SUDO journalctl -u vedetta-sensor -n 40 --no-pager 2>/dev/null >&2 || true
  fi
  die "post-install health check failed; the service is not running correctly (see the log above). Fix the dependency, then re-run this installer with --core $CORE_URL to repair the service (it rewrites the PATH and re-checks — no new enrollment code needed)."
fi
