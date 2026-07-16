#!/usr/bin/env bash
#
# Vedetta Sensor installer.
#
# On Linux, prefers a checksummed prebuilt binary from the latest GitHub release
# and falls back to building from source (installing Go + libpcap) when no asset
# matches this arch. On macOS there is no prebuilt Darwin release asset, so the
# sensor is always built from source (Go via go.dev; macOS ships libpcap).
# Homebrew, when needed for nmap, is run as the invoking user — never as root.
# Download install.sh and checksums.txt from the same published GitHub release,
# verify the install.sh manifest entry, and only then execute it with sudo. See
# the repository README for the complete copy/paste flow. Do not curl-to-sudo.
#
# Invocation after the README's release-asset checksum verification:
#   RELEASE_TAG=v0.1.0-beta.4
#   sudo env VEDETTA_RELEASE_TAG="$RELEASE_TAG" bash install.sh \
#     --core http://YOUR-CORE-IP:8080
#
#   sudo ./install.sh --core http://YOUR-CORE-IP:8080 --enroll-code-file /secure/code
#                     [--reset] [--no-service] [--build-from-source] [--ref TAG]
#
# Enrollment secrets must not be command-line arguments. Use --enroll-code-file
# (a mode-0600 regular file) or --enroll-code-stdin. The latter cannot share stdin
# with a curl-to-shell pipeline; download and review this installer first.
#
set -euo pipefail

# Sanitize command lookup before the first external utility runs. sudo commonly
# supplies secure_path, but the installer must not rely on host-specific sudoers
# policy while executing as root. The mocked suite opts out explicitly.
if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" != "1" ]; then
  PATH="/usr/bin:/bin:/usr/sbin:/sbin"
  export PATH
fi

REPO="MahdiHedhli/vedetta"
CORE_URL=""
SENSOR_CIDR="${VEDETTA_SENSOR_CIDR:-auto}"
ENROLL_CODE=""
ENROLL_CODE_FILE=""
ENROLL_CODE_STDIN=false
RESET=false
INSTALL_SERVICE=true
FORCE_SOURCE="${VEDETTA_BUILD_FROM_SOURCE:-0}"
REF="${VEDETTA_REF:-}"
REF_EXPLICIT=false
[ -n "$REF" ] && { REF_EXPLICIT=true; FORCE_SOURCE=1; }
# The platform default is selected after uname. Test/custom destinations remain
# supported, but production paths are rejected unless every ancestor is root-owned
# and non-writable by group/other.
BIN_DIR="${VEDETTA_BIN_DIR:-}"

# Acquisition happens before the installation transaction is armed. Track every
# private download/build directory from the moment it is created so success,
# validation failures, and early build failures all remove it. The transaction
# EXIT handler below calls the same cleanup after it replaces this early trap.
# Bash 3.2 (the macOS system Bash) treats expansion of an empty array as an
# unbound variable under `set -u`, so retain one ignored sentinel element.
ACQUISITION_DIRS=("")
cleanup_acquisition() {
  local path
  for path in "${ACQUISITION_DIRS[@]}"; do
    [ -z "$path" ] || rm -rf -- "$path" 2>/dev/null || true
  done
  ACQUISITION_DIRS=("")
}
trap cleanup_acquisition EXIT

die() { echo "ERROR: $*" >&2; exit 1; }

# The service token has one platform-defined, root-only location. Allowing an
# inherited environment variable to redirect it to /etc/passwd, a shared
# directory, or another credential path would turn the privileged installer
# into a file writer. Isolated installer tests opt in explicitly below.
if [ -n "${VEDETTA_SENSOR_TOKEN_FILE:-}" ] \
   && [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" != "1" ]; then
  die "VEDETTA_SENSOR_TOKEN_FILE is test-only; the production installer uses the fixed Vedetta state directory"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --core)              CORE_URL="${2:-}"; shift 2 ;;
    --cidr)              SENSOR_CIDR="${2:-}"; shift 2 ;;
    --enroll-code-file)  ENROLL_CODE_FILE="${2:-}"; shift 2 ;;
    --enroll-code-stdin) ENROLL_CODE_STDIN=true; shift ;;
    --enroll-code)
      [ "${VEDETTA_ALLOW_LEGACY_ENROLL_CODE_ARG:-0}" = "1" ] \
        || die "--enroll-code exposes the one-time secret in the installer process list and is disabled. Use --enroll-code-file /path/to/mode-0600-file or --enroll-code-stdin."
      echo "WARNING: --enroll-code is deprecated and exposes the code in process listings; migrate to --enroll-code-file or --enroll-code-stdin." >&2
      ENROLL_CODE="${2:-}"; shift 2
      ;;
    --ref)               REF="${2:-}"; REF_EXPLICIT=true; FORCE_SOURCE=1; shift 2 ;;
    --reset)             RESET=true; shift ;;
    --no-service)        INSTALL_SERVICE=false; shift ;;
    --build-from-source) FORCE_SOURCE=1; shift ;;
    -h|--help)           grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                   die "unknown option: $1" ;;
  esac
done

[ -n "$CORE_URL" ] || die "missing --core http://YOUR-CORE-IP:8080"

case "$CORE_URL" in
  [Hh][Tt][Tt][Pp]://*|[Hh][Tt][Tt][Pp][Ss]://*) ;;
  *) die "--core must be an http:// or https:// URL" ;;
esac
if LC_ALL=C printf '%s' "$CORE_URL" | grep -q '[[:cntrl:]]'; then
  die "--core contains a control character"
fi
CORE_AUTHORITY="${CORE_URL#*://}"
CORE_AUTHORITY="${CORE_AUTHORITY%%[/?#]*}"
case "$CORE_AUTHORITY" in *@*) die "--core must not contain embedded credentials" ;; esac
case "$CORE_URL" in *\?*|*\#*) die "--core must not contain a query string or fragment" ;; esac
CORE_HOSTPORT="${CORE_AUTHORITY##*@}"
case "$CORE_HOSTPORT" in ''|:*) die "--core must include a hostname or IP address" ;; esac
case "$SENSOR_CIDR" in
  auto) ;;
  *:*) die "--cidr supports numeric IPv4 CIDRs only; IPv6 active discovery is not supported in this beta" ;;
  *[!0-9./]*|'') die "--cidr must be 'auto' or a numeric IPv4 CIDR" ;;
  */*) ;;
  *) die "--cidr must include a numeric IPv4 prefix length (for example, 192.0.2.0/24)" ;;
esac

UNAME_BIN=/usr/bin/uname
ID_BIN=/usr/bin/id
[ -x "$UNAME_BIN" ] || die "required system tool is missing: $UNAME_BIN"
[ -x "$ID_BIN" ] || die "required system tool is missing: $ID_BIN"
OS="$($UNAME_BIN -s)"
MACH="$($UNAME_BIN -m)"
if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ]; then
  OS="${VEDETTA_TEST_OS:-$OS}"
  MACH="${VEDETTA_TEST_ARCH:-$MACH}"
fi
case "$OS" in
  Linux)  GOOS=linux; ROOT_HOME=/root ;;
  Darwin) GOOS=darwin; ROOT_HOME=/var/root ;;
  *)      die "unsupported OS: $OS (Linux and macOS are supported)" ;;
esac
case "$MACH" in
  x86_64|amd64)  GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *)             die "unsupported architecture: $MACH" ;;
esac

if [ -z "$BIN_DIR" ]; then
  if [ "$OS" = "Darwin" ]; then
    BIN_DIR="/Library/Vedetta/bin"
  else
    BIN_DIR="/usr/local/libexec/vedetta"
  fi
fi
BIN_DEST="${BIN_DIR}/vedetta-sensor"

if [ "$REF_EXPLICIT" = true ] && [ -n "${VEDETTA_RELEASE_TAG:-}" ]; then
  die "choose one source pin: --ref/VEDETTA_REF or VEDETTA_RELEASE_TAG, not both"
fi
for requested_ref in "$REF" "${VEDETTA_RELEASE_TAG:-}"; do
  [ -z "$requested_ref" ] && continue
  case "$requested_ref" in
    -*|/*|*..*|*//*|*[!A-Za-z0-9._+/-]*)
      die "release/source ref contains an unsafe or unsupported character: $requested_ref"
      ;;
  esac
done

CURRENT_UID="$($ID_BIN -u)"
SUDO_BIN=/usr/bin/sudo
ROOT_TOOL_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ]; then
  CURRENT_UID="${VEDETTA_TEST_UID:-$CURRENT_UID}"
  SUDO_BIN="$(command -v sudo 2>/dev/null || true)"
  ROOT_TOOL_PATH="$PATH"
fi
if [ "$CURRENT_UID" -ne 0 ]; then
  [ -x "$SUDO_BIN" ] || die "run as root or install sudo"
  # Authenticate before a secret is ever piped to a root child. Subsequent root
  # invocations are non-interactive, so sudo can never consume the secret stdin.
  if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ]; then
    "$SUDO_BIN" -v </dev/null || die "mock sudo authentication failed"
  else
    "$SUDO_BIN" -v </dev/tty || die "sudo authentication failed"
  fi
fi

# Read a file-based enrollment secret with the invoking user's authority, not
# root's. This removes the useful impact of a validate/open pathname race: a
# swapped path cannot trick the privileged installer into reading a root-only
# file. A direct root invocation has no lower-privilege caller and reads as uid 0.
ENROLL_READER_UID="$CURRENT_UID"
if [ "$CURRENT_UID" -eq 0 ] && [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" != "0" ]; then
  case "$SUDO_UID" in *[!0-9]*) die "invalid SUDO_UID for enrollment-code file access" ;; esac
  ENROLL_READER_UID="$SUDO_UID"
fi

root_run() {
  local rc
  if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ]; then
    # The installer suite's manager mocks need the selected unit identity even
    # though production root commands deliberately receive a minimal environment.
    if [ "$CURRENT_UID" -eq 0 ]; then
      /usr/bin/env -i PATH="$ROOT_TOOL_PATH" HOME="${ROOT_HOME:-/root}" LANG=C LC_ALL=C \
        VEDETTA_SERVICE_PATH="${VEDETTA_SERVICE_PATH:-}" \
        VEDETTA_TEST_SYSTEMD_LOAD_STATE="${VEDETTA_TEST_SYSTEMD_LOAD_STATE:-}" \
        VEDETTA_TEST_SYSTEMD_FRAGMENT_PATH="${VEDETTA_TEST_SYSTEMD_FRAGMENT_PATH:-}" \
        VEDETTA_TEST_SYSTEMD_DROPIN_PATHS="${VEDETTA_TEST_SYSTEMD_DROPIN_PATHS:-}" \
        "$@"
      rc=$?
    else
      "$SUDO_BIN" -n /usr/bin/env -i PATH="$ROOT_TOOL_PATH" HOME="${ROOT_HOME:-/root}" LANG=C LC_ALL=C \
        VEDETTA_SERVICE_PATH="${VEDETTA_SERVICE_PATH:-}" \
        VEDETTA_TEST_SYSTEMD_LOAD_STATE="${VEDETTA_TEST_SYSTEMD_LOAD_STATE:-}" \
        VEDETTA_TEST_SYSTEMD_FRAGMENT_PATH="${VEDETTA_TEST_SYSTEMD_FRAGMENT_PATH:-}" \
        VEDETTA_TEST_SYSTEMD_DROPIN_PATHS="${VEDETTA_TEST_SYSTEMD_DROPIN_PATHS:-}" \
        "$@"
      rc=$?
    fi
    return "$rc"
  fi
  if [ "$CURRENT_UID" -eq 0 ]; then
    /usr/bin/env -i PATH="$ROOT_TOOL_PATH" HOME="${ROOT_HOME:-/root}" LANG=C LC_ALL=C "$@"
  else
    "$SUDO_BIN" -n /usr/bin/env -i PATH="$ROOT_TOOL_PATH" HOME="${ROOT_HOME:-/root}" LANG=C LC_ALL=C "$@"
  fi
}

# Preserve the existing call sites while ensuring every privileged utility is
# resolved only through the fixed system path above. Homebrew is the deliberate
# exception: brew_run drops to the authenticated invoking user.
SUDO=root_run
if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" != "1" ]; then
  PATH="$ROOT_TOOL_PATH"
  export PATH
fi

# Fixed, root-only token location shared by the one-shot enrollment step and the
# long-running service, so both agree regardless of $HOME/sudo resolution. The
# override is available only to the isolated mocked installer suite.
if [ -n "${VEDETTA_SENSOR_TOKEN_FILE:-}" ]; then
  TOKEN_FILE="$VEDETTA_SENSOR_TOKEN_FILE"
elif [ "$OS" = "Darwin" ]; then
  TOKEN_FILE="/Library/Application Support/Vedetta/sensor-token"
else
  TOKEN_FILE="/var/lib/vedetta/sensor-token"
fi
TOKEN_DIR="$(dirname "$TOKEN_FILE")"
if [ -n "${VEDETTA_SENSOR_LOG_FILE:-}" ]; then
  SENSOR_LOG="$VEDETTA_SENSOR_LOG_FILE"
elif [ "$OS" = "Darwin" ]; then
  # /var is a compatibility symlink on macOS. Use the physical path so the
  # symlink-free root-service ancestry invariant remains true.
  SENSOR_LOG="/private/var/log/vedetta-sensor.log"
else
  SENSOR_LOG="/var/log/vedetta-sensor.log"
fi
if [ -n "${VEDETTA_SENSOR_LOG_FILE:-}" ] && [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" != "1" ]; then
  die "VEDETTA_SENSOR_LOG_FILE is test-only; set VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 explicitly in an isolated test"
fi
if [ "$OS" = "Darwin" ]; then
  DEFAULT_SERVICE_FILE="/Library/LaunchDaemons/com.vedetta.sensor.plist"
  SERVICE_FILE="${VEDETTA_PLIST_PATH:-$DEFAULT_SERVICE_FILE}"
else
  DEFAULT_SERVICE_FILE="/etc/systemd/system/vedetta-sensor.service"
  SERVICE_FILE="${VEDETTA_SERVICE_PATH:-$DEFAULT_SERVICE_FILE}"
fi
if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ]; then
  # Keep isolated fixtures from probing a developer workstation's real service.
  DEFAULT_SERVICE_FILE="${VEDETTA_TEST_DEFAULT_SERVICE_FILE:-$SERVICE_FILE}"
elif [ -n "${VEDETTA_TEST_DEFAULT_SERVICE_FILE:-}" ]; then
  die "VEDETTA_TEST_DEFAULT_SERVICE_FILE is test-only and requires VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1"
fi
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
  local brew_bin brew_user brew_uid
  brew_bin="$(find_brew)" || die "Homebrew is required on macOS but 'brew' was not found. Install it from https://brew.sh (or pre-install the dependency), then re-run."
  require_clean_absolute_path "Homebrew executable" "$brew_bin"
  [ -x "$brew_bin" ] || die "Homebrew is not executable: $brew_bin"
  if [ "$CURRENT_UID" -ne 0 ]; then
    /usr/bin/env -i PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" USER="${USER:-}" LOGNAME="${LOGNAME:-}" "$brew_bin" "$@"
    return
  fi
  brew_user="${SUDO_USER:-}"
  if [ -z "$brew_user" ] || [ "$brew_user" = "root" ]; then
    die "Refusing to run Homebrew as root (brew forbids it). Re-run this installer with sudo from your normal account — e.g. 'sudo bash install.sh --core ...' so \$SUDO_USER is set — or pre-install the dependency yourself: brew install <pkg>."
  fi
  case "$brew_user" in *[!A-Za-z0-9._-]*|-*) die "invalid SUDO_USER for Homebrew: $brew_user" ;; esac
  if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] && [ -n "${VEDETTA_TEST_BREW_UID:-}" ]; then
    brew_uid="$VEDETTA_TEST_BREW_UID"
  else
    brew_uid="$($ID_BIN -u "$brew_user" 2>/dev/null)" || die "SUDO_USER does not name a local account: $brew_user"
  fi
  [ "$brew_uid" != "0" ] || die "refusing to run Homebrew as uid 0"
  if [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" != "$brew_uid" ]; then
    die "SUDO_USER/SUDO_UID mismatch; refusing to choose a Homebrew account"
  fi
  "$SUDO_BIN" -n -H -u "$brew_user" -- /usr/bin/env -i \
    PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" USER="$brew_user" LOGNAME="$brew_user" \
    "$brew_bin" "$@"
}

pkg_install() {
  # pkg_install <apt-name> <dnf-name> <pacman-name> <brew-name>
  if [ "$OS" = "Darwin" ]; then
    brew_run list "$4" >/dev/null 2>&1 || brew_run install "$4"
  elif command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq && $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$1"
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y "$2"
  elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -S --noconfirm "$3"
  else
    die "no supported package manager found; install '$1' manually"
  fi
}

# A root service must never search Homebrew/Linuxbrew or another user-writable
# directory for executables. The sensor receives nmap's absolute path separately and
# drops privileges for that child; PATH itself remains system-only.
DAEMON_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
if [ -n "${VEDETTA_DAEMON_PATH:-}" ] && [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" != "1" ]; then
  die "VEDETTA_DAEMON_PATH is test-only; set VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 explicitly in an isolated test"
fi
if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] && [ -n "${VEDETTA_DAEMON_PATH:-}" ]; then
  DAEMON_PATH="$VEDETTA_DAEMON_PATH"
fi

path_owner_mode() {
  if [ "$OS" = "Darwin" ]; then
    $SUDO stat -f '%u %Lp' "$1"
  else
    $SUDO stat -c '%u %a' "$1"
  fi
}

require_clean_absolute_path() {
  local label="$1" path="$2"
  case "$path" in
    /*) ;;
    *) die "$label must be an absolute path: $path" ;;
  esac
  case "/${path#/}/" in
    *'//'*|*'/./'*|*'/../'*) die "$label must not contain empty, '.' or '..' path components: $path" ;;
  esac
  if LC_ALL=C printf '%s' "$path" | grep -q '[[:cntrl:]]'; then
    die "$label contains a control character"
  fi
}

# Walk the lexical path from / with lstat-style symlink checks. This is performed
# both before and after each mkdir. Once the nearest existing directory is proven
# root-owned and non-writable, an unprivileged process cannot win the remaining
# create/check race by substituting a symlink.
validate_root_owned_path() {
  if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
     && [ "${VEDETTA_TEST_ENFORCE_PATH_VALIDATION:-0}" != "1" ]; then
    return 0
  fi
  local path="$1" cur="" owner mode numeric i
  local -a parts
  require_clean_absolute_path "service path" "$path"
  IFS='/' read -r -a parts <<<"${path#/}"
  for ((i=0; i<${#parts[@]}; i++)); do
    [ -n "${parts[$i]}" ] || continue
    cur="${cur}/${parts[$i]}"
    [ ! -L "$cur" ] || die "unsafe service path: symlink component $cur"
    [ -e "$cur" ] || continue
    if [ "$i" -lt "$(( ${#parts[@]} - 1 ))" ] && [ ! -d "$cur" ]; then
      die "unsafe service path: non-directory ancestor $cur"
    fi
    read -r owner mode <<EOF
$(path_owner_mode "$cur")
EOF
    [ "$owner" = "0" ] || die "unsafe service path: $cur is owned by uid $owner, not root"
    numeric=$((8#$mode))
    [ $((numeric & 8#022)) -eq 0 ] || die "unsafe service path: $cur is group/world-writable (mode $mode)"
  done
}

ensure_secure_dir() {
  local path="$1" mode="$2"
  validate_root_owned_path "$path"
  root_run install -d -m "$mode" "$path"
  validate_root_owned_path "$path"
  [ -d "$path" ] && [ ! -L "$path" ] || die "could not create a physical directory at $path"
}

secret_path_owner_mode() {
  if [ "$OS" = "Darwin" ]; then
    stat -f '%u %Lp' "$1"
  else
    stat -c '%u %a' "$1"
  fi
}

validate_enroll_code_file() {
	local path="$1" allowed_uid="$ENROLL_READER_UID" cur="" owner mode numeric i
  local -a parts
  require_clean_absolute_path "--enroll-code-file" "$path"
  [ -f "$path" ] && [ ! -L "$path" ] || die "--enroll-code-file must be a regular, non-symlink file"
  if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
     && [ "${VEDETTA_TEST_ENFORCE_SECRET_VALIDATION:-0}" != "1" ]; then
    return 0
  fi
	IFS='/' read -r -a parts <<<"${path#/}"
  for ((i=0; i<${#parts[@]}; i++)); do
    [ -n "${parts[$i]}" ] || continue
    cur="${cur}/${parts[$i]}"
    [ ! -L "$cur" ] || die "--enroll-code-file has a symlink component: $cur"
    [ -e "$cur" ] || die "--enroll-code-file disappeared during validation"
    read -r owner mode <<EOF
$(secret_path_owner_mode "$cur")
EOF
    if [ "$i" -lt "$(( ${#parts[@]} - 1 ))" ]; then
      [ -d "$cur" ] || die "--enroll-code-file has a non-directory ancestor: $cur"
      [ "$owner" = "0" ] || [ "$owner" = "$allowed_uid" ] \
        || die "unsafe enrollment-code ancestry: $cur is owned by uid $owner"
      numeric=$((8#$mode))
      [ $((numeric & 8#022)) -eq 0 ] \
        || die "unsafe enrollment-code ancestry: $cur is group/world-writable (mode $mode)"
		else
			[ "$owner" = "$allowed_uid" ] \
				|| die "enrollment-code file must be owned by the reading uid $allowed_uid"
      numeric=$((8#$mode))
      [ $((numeric & 8#077)) -eq 0 ] \
        || die "enrollment-code file must not be accessible by group/other (mode $mode; use chmod 600)"
    fi
	done
}

read_enrollment_code_file() {
	local path="$1" payload marker=$'\034'
	if ! payload="$(
		set +e
		if [ "$CURRENT_UID" -eq 0 ] && [ "$ENROLL_READER_UID" != "0" ]; then
			"$SUDO_BIN" -n -u "#${ENROLL_READER_UID}" -- /bin/cat "$path"
		else
			/bin/cat "$path"
		fi
		rc=$?
		printf '\034'
		exit "$rc"
	)"; then
		die "could not read --enroll-code-file as uid $ENROLL_READER_UID"
	fi
	case "$payload" in
		*"$marker") payload="${payload%"$marker"}" ;;
		*) die "could not safely delimit --enroll-code-file contents" ;;
	esac
	# Accept a conventional single trailing newline, but no second line (including
	# an empty one). Command substitution retains it because the marker follows it.
	case "$payload" in *$'\n') payload="${payload%$'\n'}" ;; esac
	case "$payload" in *$'\n'*) die "--enroll-code-file must contain exactly one line" ;; esac
	ENROLL_CODE="$payload"
}

read_enrollment_secret() {
  local sources=0 extra=""
  [ -n "$ENROLL_CODE" ] && sources=$((sources + 1))
  [ -n "$ENROLL_CODE_FILE" ] && sources=$((sources + 1))
  [ "$ENROLL_CODE_STDIN" = true ] && sources=$((sources + 1))
  [ "$sources" -le 1 ] || die "choose exactly one enrollment secret input"
	if [ -n "$ENROLL_CODE_FILE" ]; then
		validate_enroll_code_file "$ENROLL_CODE_FILE"
		read_enrollment_code_file "$ENROLL_CODE_FILE"
  elif [ "$ENROLL_CODE_STDIN" = true ]; then
    if [ -t 0 ]; then
      printf 'Enrollment code: ' >&2
      IFS= read -r -s ENROLL_CODE
      printf '\n' >&2
    else
      IFS= read -r ENROLL_CODE || true
    fi
  fi
  [ -z "$ENROLL_CODE" ] && return 0
  [ "${#ENROLL_CODE}" -le 512 ] || die "enrollment code is unexpectedly long"
  case "$ENROLL_CODE" in *[!A-Za-z0-9_-]*) die "enrollment code contains an invalid character" ;; esac
}

brew_nmap_path() {
  local prefix
  prefix="$(brew_run --prefix nmap 2>/dev/null)" || return 1
  require_clean_absolute_path "Homebrew nmap prefix" "$prefix"
  [ -x "$prefix/bin/nmap" ] || return 1
  printf '%s' "$prefix/bin/nmap"
}

resolve_nmap_path() {
  local p
  if [ -n "${VEDETTA_NMAP_PATH:-}" ]; then
    p="$VEDETTA_NMAP_PATH"
    require_clean_absolute_path "VEDETTA_NMAP_PATH" "$p"
    [ -x "$p" ] || die "VEDETTA_NMAP_PATH is not executable: $p"
    NMAP_PATH="$p"
    return 0
  fi
  if [ "$OS" = "Darwin" ]; then
    p="$(brew_nmap_path)" || return 1
    NMAP_PATH="$p"
    return 0
  fi
  for p in /usr/bin/nmap /bin/nmap /usr/sbin/nmap /sbin/nmap; do
    if [ -x "$p" ]; then NMAP_PATH="$p"; return 0; fi
  done
  return 1
}

ensure_nmap() {
  resolve_nmap_path && return
  echo "==> installing nmap"
  pkg_install nmap nmap nmap nmap
  resolve_nmap_path || die "nmap was installed but no executable could be resolved (macOS: brew --prefix nmap; Linux: /usr/bin/nmap). Set VEDETTA_NMAP_PATH to an absolute executable only for a deliberate custom installation."
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

is_nonzero_pid() {
  case "${1:-}" in ''|*[!0-9]*|0) return 1 ;; *) return 0 ;; esac
}

launchd_pid() {
  $SUDO launchctl print system/com.vedetta.sensor 2>/dev/null \
    | awk '/^[[:space:]]*pid = [0-9]+/ { print $3; exit }'
}

systemd_pid() {
  $SUDO systemctl show -p MainPID vedetta-sensor 2>/dev/null \
    | sed -n 's/^MainPID=//p' | head -1
}

# Require the same nonzero service-manager PID for several consecutive polls. A
# replacement process after a crash never inherits the previous process's readiness.
# Poll counts are overridable only to make the fully mocked installer suite fast.
health_check() {
  if [ "${VEDETTA_SKIP_HEALTHCHECK:-0}" = "1" ]; then
    [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
      || die "VEDETTA_SKIP_HEALTHCHECK is test-only and requires VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1"
    return 0
  fi
  local max_polls=13 stable_needed=3 poll_seconds=2
  if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ]; then
    max_polls="${VEDETTA_HEALTH_MAX_POLLS:-13}"
    stable_needed="${VEDETTA_HEALTH_STABLE_POLLS:-3}"
    poll_seconds="${VEDETTA_HEALTH_POLL_SECONDS:-2}"
  fi
  local first_pid="" pid="" stable=0 active="" i
  for ((i=0; i<max_polls; i++)); do
    if [ "$OS" = "Darwin" ]; then
      # grep must consume the full stream: with pipefail, grep -q can close the
      # pipe early and turn tail's SIGPIPE into a false pipeline result.
      launchd_log_since_install | grep -E 'device scanner unavailable|Could not initialize Core client' >/dev/null && return 1
      if ! launchd_log_since_install | grep 'Device scanner ready' >/dev/null; then
        sleep "$poll_seconds"
        continue
      fi
      pid="$(launchd_pid || true)"
    else
      active="$($SUDO systemctl is-active vedetta-sensor 2>/dev/null || true)"
      [ "$active" = "active" ] || { sleep "$poll_seconds"; continue; }
      pid="$(systemd_pid || true)"
    fi
    is_nonzero_pid "$pid" || { sleep "$poll_seconds"; continue; }
    if [ -z "$first_pid" ]; then
      first_pid="$pid"
      stable=1
    elif [ "$pid" != "$first_pid" ]; then
      echo "service process changed during health check ($first_pid -> $pid)" >&2
      return 1
    else
      stable=$((stable + 1))
    fi
    [ "$stable" -ge "$stable_needed" ] && return 0
    sleep "$poll_seconds"
  done
  return 1
}

# Read only bytes appended after this install started the candidate. Historical
# readiness or error lines must not determine whether the replacement is healthy.
launchd_log_since_install() {
  local start="${HEALTH_LOG_START:-0}"
  $SUDO tail -c "+$((start + 1))" "$SENSOR_LOG" 2>/dev/null
}

if [ "${VEDETTA_TEST_HEALTH_ONLY:-0}" = "1" ]; then
  [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
    || die "VEDETTA_TEST_HEALTH_ONLY requires VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1"
  health_check
  exit $?
fi

# ---------------------------------------------------------------------------
# Path 1: prebuilt binary from the latest release, checksum-verified.
# ---------------------------------------------------------------------------
BINARY=""
BINARY_KIND=""
RESOLVED_RELEASE_TAG=""
resolve_published_release_ref() {
  local tag
  command -v curl >/dev/null 2>&1 || die "curl is required to resolve a published release; pass --ref <published-tag> to pin one explicitly"
  tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" 2>/dev/null \
         | grep -m1 -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' \
         | cut -d'"' -f4)" || true
  [ -n "$tag" ] || die "could not resolve a published Vedetta release. Pass --ref <published-tag> (or VEDETTA_RELEASE_TAG=<tag>); refusing to compile mutable main"
  printf '%s' "$tag"
}

require_published_release_ref() {
  command -v curl >/dev/null 2>&1 || die "curl is required to validate source release '$1'"
  curl -fsSL -o /dev/null "https://api.github.com/repos/${REPO}/releases/tags/$1" 2>/dev/null \
    || die "source ref '$1' is not a published GitHub release (or could not be verified); refusing a mutable/unpublished source build"
}

try_prebuilt() {
  command -v curl >/dev/null 2>&1 || return 1
  local base asset tmp sums url selected_tag
  asset="vedetta-sensor_${GOOS}_${GOARCH}.tar.gz"
  if [ -n "${VEDETTA_RELEASE_TAG:-}" ]; then
    # Explicit pin (mirrors install.ps1 -Tag).
    base="https://github.com/${REPO}/releases/download/${VEDETTA_RELEASE_TAG}"
    selected_tag="$VEDETTA_RELEASE_TAG"
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
    selected_tag="${base##*/}"
  fi
  [ -n "$selected_tag" ] || return 1
  tmp="$(mktemp -d)"
  ACQUISITION_DIRS+=("$tmp")
  echo "==> downloading prebuilt ${asset} (${base##*/download/})"
  curl -fsSL -o "${tmp}/${asset}" "${base}/${asset}" || { rm -rf "$tmp"; return 1; }
  curl -fsSL -o "${tmp}/checksums.txt" "${base}/checksums.txt" || { rm -rf "$tmp"; return 1; }
  echo "==> verifying checksum"
  sums="sha256sum"; command -v sha256sum >/dev/null 2>&1 || sums="shasum -a 256"
  ( cd "$tmp" && grep " ${asset}\$" checksums.txt | $sums -c - ) || { echo "!! checksum FAILED"; rm -rf "$tmp"; return 1; }
  tar -xzf "${tmp}/${asset}" -C "$tmp"
  [ -f "${tmp}/vedetta-sensor" ] || { rm -rf "$tmp"; return 1; }
  BINARY="${tmp}/vedetta-sensor"
  BINARY_KIND="prebuilt"
  # Persist the exact release decision in memory before any ABI fallback. Without
  # this, a new release published between download and rebuild could select a
  # different source tree than the checksum-verified artifact we just chose.
  RESOLVED_RELEASE_TAG="$selected_tag"
}

# ---------------------------------------------------------------------------
# Path 2: build from source (installs Go + libpcap as needed).
# ---------------------------------------------------------------------------
valid_go_version() {
	local version="$1" numeric major minor patch extra
	case "$version" in go*) ;; *) return 1 ;; esac
	numeric="${version#go}"
	case "$numeric" in ''|*[!0-9.]*|.*|*.|*..*) return 1 ;; esac
	IFS=. read -r major minor patch extra <<<"$numeric"
	[ -n "$major" ] && [ -n "$minor" ] && [ -n "$patch" ] && [ -z "${extra:-}" ] \
		|| return 1
	case "$major:$minor:$patch" in *[!0-9:]*) return 1 ;; esac
}

go_version_sufficient() {
	local binary="$1" version numeric major minor
	version="$("$binary" env GOVERSION 2>/dev/null || true)"
	valid_go_version "$version" || return 1
	numeric="${version#go}"
	major="${numeric%%.*}"
	numeric="${numeric#*.}"
	minor="${numeric%%.*}"
	case "$major:$minor" in *[!0-9:]*|:*) return 1 ;; esac
	[ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 25 ]; }
}

go_candidate_usable() {
	local candidate="$1"
	[ -x "$candidate" ] && [ ! -L "$candidate" ] \
		&& (validate_root_owned_path "$candidate") >/dev/null 2>&1
}

if [ "${VEDETTA_TEST_GO_VERSION+x}" = "x" ]; then
	[ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
		|| die "VEDETTA_TEST_GO_VERSION requires VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1"
	valid_go_version "$VEDETTA_TEST_GO_VERSION" || die "invalid test Go version"
	printf 'valid\n'
	exit 0
fi
if [ "${VEDETTA_TEST_GO_CANDIDATE+x}" = "x" ]; then
	[ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
		|| die "VEDETTA_TEST_GO_CANDIDATE requires VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1"
	go_candidate_usable "$VEDETTA_TEST_GO_CANDIDATE" || die "unusable test Go candidate"
	printf 'usable\n'
	exit 0
fi

ensure_go() {
	local candidate ver archive tgz checksum expected actual tmp
	for candidate in /usr/local/go/bin/go /usr/bin/go; do
		# Distribution packages commonly expose /usr/bin/go as a symlink. Do not
		# abort an otherwise valid install on that host and do not follow a path we
		# cannot validate component-by-component; safely skip it and use the private,
		# checksum-verified toolchain below instead.
		go_candidate_usable "$candidate" || continue
		if go_version_sufficient "$candidate"; then
			GO_BIN="$candidate"
			return 0
		fi
	done

	echo "==> downloading a private checksum-verified Go toolchain"
	# Keep the build toolchain inside a private temporary directory. Never remove or
	# replace /usr/local/go: installer failure and rollback must not mutate a host-wide
	# developer toolchain. go.dev publishes the current version; dl.google.com serves
	# the matching archive checksum over TLS.
	ver="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
	valid_go_version "$ver" || die "go.dev returned an invalid Go version"
	archive="${ver}.${GOOS}-${GOARCH}.tar.gz"
	tmp="$(mktemp -d)"
	ACQUISITION_DIRS+=("$tmp")
	tgz="${tmp}/${archive}"
	checksum="${tmp}/${archive}.sha256"
	curl -fsSL -o "$checksum" "https://dl.google.com/go/${archive}.sha256" \
		|| die "Go checksum download failed"
	expected="$(tr -d '[:space:]' <"$checksum")"
	case "$expected" in ''|*[!0-9a-f]*) die "Go checksum response is invalid" ;; esac
	[ "${#expected}" -eq 64 ] || die "Go checksum response has the wrong length"
	curl -fsSL -o "$tgz" "https://dl.google.com/go/${archive}" || die "Go download failed"
	if command -v sha256sum >/dev/null 2>&1; then
		actual="$(sha256sum "$tgz" | awk '{print $1}')"
	else
		actual="$(shasum -a 256 "$tgz" | awk '{print $1}')"
	fi
	[ "$actual" = "$expected" ] || die "Go toolchain checksum verification failed"
	mkdir -p "${tmp}/root"
	tar -C "${tmp}/root" -xzf "$tgz"
	GO_BIN="${tmp}/root/go/bin/go"
	[ -x "$GO_BIN" ] && go_version_sufficient "$GO_BIN" \
		|| die "verified Go archive did not contain a usable Go 1.25+ toolchain"
}

select_source_ref() {
  local source_ref="$REF"
  [ -n "$source_ref" ] || source_ref="$RESOLVED_RELEASE_TAG"
  [ -n "$source_ref" ] || source_ref="${VEDETTA_RELEASE_TAG:-}"
  [ -n "$source_ref" ] || source_ref="$(resolve_published_release_ref)"
  require_published_release_ref "$source_ref"
  printf '%s' "$source_ref"
}

build_from_source() {
  command -v git >/dev/null 2>&1 || pkg_install git git git git
  if [ "$OS" = "Linux" ]; then
    echo "==> installing libpcap headers"
    pkg_install libpcap-dev libpcap-devel libpcap libpcap  # macOS ships libpcap
  fi
  ensure_go
  local src source_ref
  source_ref="$(select_source_ref)"
  RESOLVED_RELEASE_TAG="$source_ref"
  src="$(mktemp -d)"
  ACQUISITION_DIRS+=("$src")
  echo "==> cloning ${REPO}@${source_ref}"
  git clone --depth 1 --branch "$source_ref" "https://github.com/${REPO}" "${src}/vedetta" >/dev/null 2>&1 \
    || die "git clone failed for requested published ref '${source_ref}'; refusing to fall back to mutable main"
  echo "==> building vedetta-sensor (CGO)"
	( cd "${src}/vedetta/sensor" && CGO_ENABLED=1 "$GO_BIN" build -trimpath -ldflags="-X main.buildVersion=${source_ref}" -o "${src}/vedetta-sensor" ./cmd/vedetta-sensor )
  BINARY="${src}/vedetta-sensor"
  BINARY_KIND="source"
}

binary_runtime_ok() {
  [ "$OS" = "Linux" ] || return 0
  command -v ldd >/dev/null 2>&1 || return 0
  local out
  out="$(ldd "$1" 2>&1 || true)"
  if printf '%s\n' "$out" | grep -qi 'not found'; then
    printf '%s\n' "$out" >&2
    return 1
  fi
  return 0
}

# Compare service identities without decoding the path: scheme and authority are
# case-insensitive, while reverse-proxy paths (including a non-root trailing
# slash) remain byte-sensitive. A bare origin and its single root slash are the
# only equivalent path spellings. Query strings, fragments, credentials, and
# hostless URLs are rejected above for the requested URL and again here for the
# value recovered from an existing service definition.
normalize_core_url() {
  local raw="$1" scheme rest authority path
  case "$raw" in
    [Hh][Tt][Tt][Pp]://*) scheme=http ;;
    [Hh][Tt][Tt][Pp][Ss]://*) scheme=https ;;
    *) return 1 ;;
  esac
  case "$raw" in *\?*|*\#*) return 1 ;; esac
  rest="${raw#*://}"
  authority="${rest%%/*}"
  [ -n "$authority" ] || return 1
  case "$authority" in *@*|:*) return 1 ;; esac
  path="${rest#"$authority"}"
  authority="$(LC_ALL=C printf '%s' "$authority" | tr '[:upper:]' '[:lower:]')"
  [ "$path" = "/" ] && path=""
  printf '%s' "${scheme}://${authority}${path}"
}

xml_unescape() {
  local input="$1" output="" prefix
  # Scan left-to-right so each generated XML entity is decoded exactly once.
  # Bash 5 can treat '&' specially inside ${value//pattern/replacement} while
  # macOS ships Bash 3.2; this scanner has identical behavior on both. In
  # particular, "&amp;quot;" becomes the literal text "&quot;", never a quote.
  while [ -n "$input" ]; do
    case "$input" in
      *'&'*)
        prefix="${input%%&*}"
        output="${output}${prefix}"
        input="${input#"$prefix"}"
        ;;
      *)
        output="${output}${input}"
        break
        ;;
    esac
    case "$input" in
      '&quot;'*) output="${output}\""; input="${input#&quot;}" ;;
      '&apos;'*) output="${output}'";  input="${input#&apos;}" ;;
      '&lt;'*)   output="${output}<";  input="${input#&lt;}" ;;
      '&gt;'*)   output="${output}>";  input="${input#&gt;}" ;;
      '&amp;'*)  output="${output}&";  input="${input#&amp;}" ;;
      *)        output="${output}&";  input="${input#?}" ;;
    esac
  done
  printf '%s' "$output"
}

validate_launchd_core_arguments() {
  local count="$1" binary="$2" flag="$3" core="$4"
  local cidr_flag="${5:-}" cidr="${6:-}" dns="${7:-}" passive="${8:-}"
  [ -n "$binary" ] && [ "$flag" = "--core" ] && [ -n "$core" ] || return 1
  case "$count" in
    3) ;;
    7)
      [ "$cidr_flag" = "--cidr" ] && [ -n "$cidr" ] \
        && [ "$dns" = "--dns" ] && [ "$passive" = "--passive-discovery" ] \
        || return 1
      ;;
    *) return 1 ;;
  esac
  printf '%s' "$core"
}

extract_launchd_core_fallback() {
  local document compact marker rest body encoded argument
  local count=0 arg0="" arg1="" arg2="" arg3="" arg4="" arg5="" arg6=""
  document="$($SUDO /bin/cat "$SERVICE_FILE")" || return 1
  # Parse the whole ProgramArguments array and accept only the exact historical
  # three-argument or current seven-argument shape. A substring search is unsafe:
  # Go's flag parser also accepts --core=VALUE and -core=VALUE overrides.
  compact="$(LC_ALL=C printf '%s' "$document" | tr -d '\r\n\t')"
  marker='<key>ProgramArguments</key><array>'
  case "$compact" in *"$marker"*) ;; *) return 1 ;; esac
  rest="${compact#*"$marker"}"
  case "$rest" in *"$marker"*) return 1 ;; esac
  body="${rest%%</array>*}"
  [ "$body" != "$rest" ] || return 1
  while :; do
    body="${body#"${body%%[![:space:]]*}"}"
    [ -n "$body" ] || break
    case "$body" in '<string>'*'</string>'*) ;; *) return 1 ;; esac
    encoded="${body#<string>}"
    encoded="${encoded%%</string>*}"
    argument="$(xml_unescape "$encoded")" || return 1
    case "$count" in
      0) arg0="$argument" ;;
      1) arg1="$argument" ;;
      2) arg2="$argument" ;;
      3) arg3="$argument" ;;
      4) arg4="$argument" ;;
      5) arg5="$argument" ;;
      6) arg6="$argument" ;;
      *) return 1 ;;
    esac
    count=$((count + 1))
    body="${body#*</string>}"
  done
  validate_launchd_core_arguments "$count" "$arg0" "$arg1" "$arg2" "$arg3" "$arg4" "$arg5" "$arg6"
}

extract_launchd_core_plistbuddy() {
  local index=0 count=0 argument
  local arg0="" arg1="" arg2="" arg3="" arg4="" arg5="" arg6=""
  while [ "$index" -le 7 ]; do
    argument="$($SUDO /usr/libexec/PlistBuddy -c "Print :ProgramArguments:$index" "$SERVICE_FILE" 2>/dev/null)" \
      || break
    case "$index" in
      0) arg0="$argument" ;;
      1) arg1="$argument" ;;
      2) arg2="$argument" ;;
      3) arg3="$argument" ;;
      4) arg4="$argument" ;;
      5) arg5="$argument" ;;
      6) arg6="$argument" ;;
      *) return 1 ;;
    esac
    count=$((count + 1))
    index=$((index + 1))
  done
  validate_launchd_core_arguments "$count" "$arg0" "$arg1" "$arg2" "$arg3" "$arg4" "$arg5" "$arg6"
}

extract_launchd_core() {
  if [ -x /usr/libexec/PlistBuddy ] \
     && { [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" != "1" ] \
          || [ "${VEDETTA_TEST_FORCE_PLIST_FALLBACK:-0}" != "1" ]; }; then
    extract_launchd_core_plistbuddy
    return
  fi
  extract_launchd_core_fallback
}

decode_generated_systemd_core() {
  local input="$1" output="" ch next suffix i=1 length="${#1}"
  [ "${input:0:1}" = '"' ] || return 1
  while [ "$i" -lt "$length" ]; do
    ch="${input:$i:1}"
    case "$ch" in
      '"')
        suffix="${input:$((i + 1))}"
        case "$suffix" in ' --cidr "'*'" --dns --passive-discovery') ;; *) return 1 ;; esac
        suffix="${suffix# --cidr \"}"
        suffix="${suffix%\" --dns --passive-discovery}"
        # Active discovery accepts auto or numeric IPv4 syntax. Keep this parser
        # deliberately narrower than systemd's token language so no extra option
        # can be smuggled into the exact generated tail.
        case "$suffix" in ''|*[!A-Za-z0-9.,:/_-]*) return 1 ;; esac
        printf '%s' "$output"
        return 0
        ;;
      \\)
        [ "$((i + 1))" -lt "$length" ] || return 1
        next="${input:$((i + 1)):1}"
        if [ "$next" != "\\" ] && [ "$next" != '"' ]; then return 1; fi
        output="${output}${next}"
        i=$((i + 2))
        ;;
      '$'|%)
        [ "$((i + 1))" -lt "$length" ] || return 1
        next="${input:$((i + 1)):1}"
        [ "$next" = "$ch" ] || return 1
        output="${output}${ch}"
        i=$((i + 2))
        ;;
      *)
        output="${output}${ch}"
        i=$((i + 1))
        ;;
    esac
  done
  return 1
}

decode_legacy_systemd_core() {
  local input="$1" delimiter=' --cidr ' token suffix
  case "$input" in *"$delimiter"*) ;; *) return 1 ;; esac
  token="${input%%"$delimiter"*}"
  [ -n "$token" ] || return 1
  suffix="${input#"$token"}"
  # The old installer emitted the Core as one unquoted systemd token. Accept
  # only its exact historical argument tail. Go's flag parser also accepts
  # -core, -core=..., and --core=..., so a blacklist of later overrides would
  # be ambiguous and unsafe for this one-time compatibility path.
  [ "$suffix" = ' --cidr auto --dns --passive-discovery' ] || return 1
  # The legacy Core itself was one bare systemd token.
  case "$token" in *[[:space:][:cntrl:]]*) return 1 ;; esac
  case "$token" in *\"*|*\'*|*\\*) return 1 ;; esac
  printf '%s' "$token"
}

validate_systemd_exec_prefix() {
  local input="$1" token ch next i=1 length
  token="${input#ExecStart=}"
  [ "$token" != "$input" ] && [ -n "$token" ] || return 1
  if [ "${token:0:1}" != '"' ]; then
    # The sole historical unquoted installer path. Accepting a generic prefix
    # would also accept positional argv, which makes Go stop parsing before
    # --core and silently use its localhost default.
    [ "$token" = "/usr/local/bin/vedetta-sensor" ]
    return
  fi
  length="${#token}"
  while [ "$i" -lt "$length" ]; do
    ch="${token:$i:1}"
    case "$ch" in
      '"') [ "$i" -gt 1 ] && [ "$((i + 1))" -eq "$length" ]; return ;;
      \\)
        [ "$((i + 1))" -lt "$length" ] || return 1
        next="${token:$((i + 1)):1}"
        if [ "$next" != "\\" ] && [ "$next" != '"' ]; then return 1; fi
        i=$((i + 2))
        ;;
      '$'|%)
        [ "$((i + 1))" -lt "$length" ] || return 1
        next="${token:$((i + 1)):1}"
        [ "$next" = "$ch" ] || return 1
        i=$((i + 2))
        ;;
      [[:cntrl:]]) return 1 ;;
      *) i=$((i + 1)) ;;
    esac
  done
  return 1
}

extract_systemd_core() {
  local document count line prefix rest
  document="$($SUDO /bin/cat "$SERVICE_FILE")" || return 1
  count="$(LC_ALL=C printf '%s\n' "$document" | grep -c '^ExecStart=' || true)"
  [ "$count" = "1" ] || return 1
  line="$(LC_ALL=C printf '%s\n' "$document" | grep '^ExecStart=')"
  prefix="${line%% --core *}"
  rest="${line#* --core }"
  [ "$rest" != "$line" ] || return 1
  validate_systemd_exec_prefix "$prefix" || return 1
  case "$rest" in
    '"'*) decode_generated_systemd_core "$rest" ;;
    *)   decode_legacy_systemd_core "$rest" ;;
  esac
}

systemd_targeted_dropin_exists() {
  local base dir
  local -a roots
  if [ -n "${VEDETTA_TEST_SYSTEMD_DROPIN_ROOT:-}" ]; then
    [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
      || die "VEDETTA_TEST_SYSTEMD_DROPIN_ROOT is test-only and requires VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1"
    roots=("$VEDETTA_TEST_SYSTEMD_DROPIN_ROOT")
  else
    roots=(/etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system)
  fi
  for base in "${roots[@]}"; do
    for dir in "$base/vedetta-sensor.service.d" "$base/vedetta-.service.d"; do
      # Test with root authority: systemd can read a 0700 drop-in directory that
      # the invoking operator cannot enumerate. Reject the targeted directory as
      # a whole so a not-yet-reloaded ExecStart override cannot appear only after
      # this guard has spent an enrollment code.
      if $SUDO test -d "$dir" || $SUDO test -L "$dir"; then
        return 0
      fi
    done
  done
  return 1
}

guard_systemd_manager_config() {
  local metadata fragment dropins
  managed_service_registered || return 0
  metadata="$($SUDO systemctl show -p FragmentPath -p DropInPaths vedetta-sensor 2>/dev/null)" \
    || die "systemd knows vedetta-sensor but its effective configuration could not be inspected"
  fragment="$(LC_ALL=C printf '%s\n' "$metadata" | sed -n 's/^FragmentPath=//p' | head -1)"
  dropins="$(LC_ALL=C printf '%s\n' "$metadata" | sed -n 's/^DropInPaths=//p' | head -1)"
  [ -n "$fragment" ] \
    || die "systemd knows vedetta-sensor but did not expose its FragmentPath; refusing an update with an unknown rollback target"
  [ "$fragment" = "$SERVICE_FILE" ] \
    || die "systemd is using $fragment instead of $SERVICE_FILE; move the effective unit to the supported path before updating"
  case "$dropins" in
    *'/vedetta-sensor.service.d/'*|*'/vedetta-.service.d/'*)
      die "systemd reports a Vedetta-specific drop-in that can override the effective sensor command; remove or fold it into the supported installer configuration before updating"
      ;;
  esac
}

guard_existing_service_core() {
  [ "$INSTALL_SERVICE" = true ] || return 0
  if [ "$SERVICE_FILE" != "$DEFAULT_SERVICE_FILE" ] && $SUDO test -f "$DEFAULT_SERVICE_FILE"; then
    die "the default Vedetta service definition already exists at $DEFAULT_SERVICE_FILE; refusing to transact a different override path"
  fi
  if [ "$OS" != "Darwin" ]; then
    systemd_targeted_dropin_exists \
      && die "a Vedetta-specific systemd drop-in can override the effective sensor command; remove or fold it into the supported installer configuration before updating"
  fi
  if ! $SUDO test -f "$SERVICE_FILE"; then
    managed_service_registered \
      && die "the service manager already knows Vedetta but $SERVICE_FILE is absent; restore or remove that registration before installing"
    return 0
  fi
  local existing requested_normalized existing_normalized
  if [ "$OS" = "Darwin" ]; then
    existing="$(extract_launchd_core)" \
      || die "existing LaunchDaemon has no parseable --core URL; refusing to update before its rollback target is known"
  else
    guard_systemd_manager_config
    existing="$(extract_systemd_core)" \
      || die "existing systemd service has no parseable --core URL; refusing to update before its rollback target is known"
  fi
  requested_normalized="$(normalize_core_url "$CORE_URL")" \
    || die "requested --core URL could not be normalized"
  existing_normalized="$(normalize_core_url "$existing")" \
    || die "existing service has an invalid --core URL; refusing to update before its rollback target is known"
  if [ "$existing_normalized" != "$requested_normalized" ]; then
    die "changing --core is a credential migration, not an update; use the existing Core URL or perform a deliberate stopped-service migration"
  fi
}

managed_service_registered() {
  local load_state active pid
  if [ "$OS" = "Darwin" ]; then
    $SUDO launchctl print system/com.vedetta.sensor >/dev/null 2>&1
    return
  fi
  load_state="$($SUDO systemctl show -p LoadState vedetta-sensor 2>/dev/null \
    | sed -n 's/^LoadState=//p' | head -1)"
  case "$load_state" in ''|not-found) ;; *) return 0 ;; esac
  # Older/minimal systemctl implementations may not expose LoadState. A live
  # process must still fail closed even when the unit file has already vanished.
  active="$($SUDO systemctl is-active vedetta-sensor 2>/dev/null || true)"
  pid="$(systemd_pid || true)"
  case "$active" in active|activating|deactivating) return 0 ;; esac
  is_nonzero_pid "$pid"
}

if [ "${VEDETTA_TEST_SELECT_SOURCE_REF:-0}" = "1" ]; then
  [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
    || die "VEDETTA_TEST_SELECT_SOURCE_REF requires VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1"
  RESOLVED_RELEASE_TAG="${VEDETTA_TEST_RESOLVED_RELEASE_TAG:-$RESOLVED_RELEASE_TAG}"
  TEST_SOURCE_REF="$(select_source_ref)"
  printf 'ref=%s force_source=%s\n' "$TEST_SOURCE_REF" "$FORCE_SOURCE"
  exit 0
fi

# ---------------------------------------------------------------------------
# Install.
# ---------------------------------------------------------------------------
require_clean_absolute_path "binary directory" "$BIN_DIR"
require_clean_absolute_path "token file" "$TOKEN_FILE"
require_clean_absolute_path "sensor log" "$SENSOR_LOG"
require_clean_absolute_path "service definition" "$SERVICE_FILE"
validate_root_owned_path "$BIN_DIR"
validate_root_owned_path "$TOKEN_FILE"
validate_root_owned_path "$SENSOR_LOG"
validate_root_owned_path "$SERVICE_FILE"
if [ "$INSTALL_SERVICE" != true ]; then
  if $SUDO test -f "$SERVICE_FILE" \
     || { [ "$SERVICE_FILE" != "$DEFAULT_SERVICE_FILE" ] && $SUDO test -f "$DEFAULT_SERVICE_FILE"; } \
     || managed_service_registered; then
    die "a Vedetta service definition or manager registration already exists; omit --no-service so the installer can stop and update it transactionally"
  fi
fi
read_enrollment_secret
if [ "$INSTALL_SERVICE" = true ]; then
  # A token is scoped to the Core that minted it. Reject accidental Core changes
  # before dependency installation, service stop, file replacement, or code spend;
  # otherwise rollback could restore a service configured for Core A with a newly
  # enrolled Core-B token.
  guard_existing_service_core
fi
# Refuse destructive/stranded states before package installation, downloads, or
# binary replacement. `-s` rejects an interrupted zero-length token file.
if [ "$RESET" = true ] && [ -z "$ENROLL_CODE" ]; then
  die "--reset replaces the sensor credential. Also provide a bound reset code through --enroll-code-file or --enroll-code-stdin; refusing to strand the sensor."
fi
if [ "$INSTALL_SERVICE" = true ] && [ -z "$ENROLL_CODE" ] && ! $SUDO test -s "$TOKEN_FILE"; then
  die "no enrollment code and no non-empty existing token at $TOKEN_FILE. Mint a one-time code in the dashboard and provide it through --enroll-code-file or --enroll-code-stdin."
fi

ensure_nmap
ensure_libpcap_runtime

if [ -n "${VEDETTA_SENSOR_BINARY:-}" ]; then
  # Escape hatch (also used by the installer test): use a caller-supplied binary
  # instead of downloading or building one.
  BINARY="$VEDETTA_SENSOR_BINARY"
  require_clean_absolute_path "VEDETTA_SENSOR_BINARY" "$BINARY"
  validate_root_owned_path "$BINARY"
  [ -f "$BINARY" ] && [ ! -L "$BINARY" ] || die "VEDETTA_SENSOR_BINARY must be a regular, non-symlink file"
  BINARY_KIND="caller"
  echo "==> using caller-supplied binary: $BINARY"
elif [ "$OS" = "Darwin" ]; then
  # Darwin assets are not published yet. Compile exactly a published/requested tag;
  # never silently clone mutable main, even when the releases API is unavailable.
  echo "==> macOS: building the sensor from a pinned release ref"
  build_from_source
elif [ -n "${VEDETTA_RELEASE_TAG:-}" ] && [ "$FORCE_SOURCE" != "1" ]; then
  # Explicit release pin: install ONLY that pinned, checksum-verified asset. Fail
  # closed — never silently fall back to building mutable main when a pinned download
  # or checksum verification fails.
  try_prebuilt || die "pinned release ${VEDETTA_RELEASE_TAG}: asset download or checksum verification failed; refusing to fall back to a source build of main"
  echo "==> using checksum-verified prebuilt binary (${VEDETTA_RELEASE_TAG})"
elif [ "$FORCE_SOURCE" != "1" ] && try_prebuilt; then
  echo "==> using checksum-verified prebuilt binary"
else
  [ "$FORCE_SOURCE" = "1" ] || echo "==> no prebuilt release asset for ${GOOS}/${GOARCH}; building from source"
  build_from_source
fi

# Check the candidate's dynamic runtime BEFORE executing even `--version`. Fedora,
# RHEL, and Arch may provide a different libpcap SONAME than a Debian-built release.
# Rebuild against the local ABI when the downloaded prebuilt cannot resolve; never do
# that silently for a caller-supplied binary.
if ! binary_runtime_ok "$BINARY"; then
  if [ "$BINARY_KIND" = "prebuilt" ]; then
    echo "==> prebuilt libpcap ABI is incompatible with this host; rebuilding the pinned published source against the local libpcap"
    build_from_source
    binary_runtime_ok "$BINARY" || die "locally built sensor still has unresolved shared libraries; install the platform libpcap runtime and retry"
  else
    die "sensor binary has unresolved shared libraries (often a libpcap ABI mismatch). Install the platform libpcap runtime or provide a compatible binary."
  fi
fi

BIN_TXN_DIR=""
CONFIG_TXN_DIR=""
BIN_STAGE=""
BIN_BACKUP=""
CONFIG_STAGE=""
CONFIG_BACKUP=""
HAD_BINARY=0
HAD_CONFIG=0
WAS_RUNNING=0
WAS_ENABLED=0
WAS_LOADED=0
SYSTEMD_ENABLE_STATE="not-found"
LAUNCHD_DISABLED_STATE="unset"
HEALTH_LOG_START=0
ROLLBACK_ARMED=0
PRESERVE_TXN=0

stop_service() {
  if [ "$INSTALL_SERVICE" != true ]; then return 0; fi
  local max_polls=10 poll_seconds=1 i pid active
  if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ]; then
    max_polls="${VEDETTA_STOP_MAX_POLLS:-3}"
    poll_seconds="${VEDETTA_STOP_POLL_SECONDS:-0}"
  fi
  if [ "$OS" = "Darwin" ]; then
    if $SUDO launchctl print system/com.vedetta.sensor >/dev/null 2>&1; then
      if ! $SUDO launchctl bootout system/com.vedetta.sensor >/dev/null 2>&1 \
          && ! $SUDO launchctl unload "$SERVICE_FILE" >/dev/null 2>&1; then
        echo "could not request LaunchDaemon stop" >&2
        return 1
      fi
    fi
    for ((i=0; i<max_polls; i++)); do
      $SUDO launchctl print system/com.vedetta.sensor >/dev/null 2>&1 || return 0
      sleep "$poll_seconds"
    done
    echo "LaunchDaemon remained loaded after stop request" >&2
    return 1
  fi
  active="$($SUDO systemctl is-active vedetta-sensor 2>/dev/null || true)"
  pid="$(systemd_pid || true)"
  if [ "$active" = "active" ] || [ "$active" = "activating" ] || [ "$active" = "deactivating" ] || is_nonzero_pid "$pid"; then
    $SUDO systemctl stop vedetta-sensor >/dev/null 2>&1 \
      || { echo "systemd rejected the stop request" >&2; return 1; }
  fi
  for ((i=0; i<max_polls; i++)); do
    active="$($SUDO systemctl is-active vedetta-sensor 2>/dev/null || true)"
    pid="$(systemd_pid || true)"
    if [ "$active" != "active" ] && [ "$active" != "activating" ] \
       && [ "$active" != "deactivating" ] && ! is_nonzero_pid "$pid"; then
      return 0
    fi
    sleep "$poll_seconds"
  done
  echo "systemd service retained an active process after stop request" >&2
  return 1
}

rollback_install() {
  [ "$ROLLBACK_ARMED" = "1" ] || return 0
  ROLLBACK_ARMED=0
  set +e
  local rollback_failed=0 restore_complete=1 state
  echo "==> rolling back the failed sensor installation" >&2
  stop_service || { rollback_failed=1; restore_complete=0; }
	# Originals are renamed into transaction directories on the same filesystem,
	# preserving their inode metadata (ACLs, xattrs, capabilities, ownership and
	# mode). Restore whenever a backup exists, including interruption between the
	# backup rename and the candidate rename.
	if [ "$INSTALL_SERVICE" = true ]; then
		if [ "$HAD_CONFIG" = "1" ]; then
			if $SUDO test -f "$CONFIG_BACKUP"; then
				$SUDO mv -f "$CONFIG_BACKUP" "$SERVICE_FILE" || {
					echo "ERROR: could not restore the prior service configuration from $CONFIG_BACKUP" >&2
					rollback_failed=1
					restore_complete=0
				}
			else
				echo "ERROR: prior service configuration backup is missing or inaccessible: $CONFIG_BACKUP" >&2
				rollback_failed=1
				restore_complete=0
			fi
			else
				# A fresh install had neither path before this transaction. Remove
				# both so rollback is correct even if interruption lands between the
				# atomic move and any subsequent bookkeeping statement.
				$SUDO rm -f "$SERVICE_FILE" "$CONFIG_STAGE" \
					|| { rollback_failed=1; restore_complete=0; }
			fi
	fi
	if [ "$HAD_BINARY" = "1" ]; then
		if $SUDO test -f "$BIN_BACKUP"; then
			$SUDO mv -f "$BIN_BACKUP" "$BIN_DEST" || {
				echo "ERROR: could not restore the prior sensor binary from $BIN_BACKUP" >&2
				rollback_failed=1
				restore_complete=0
			}
		else
			echo "ERROR: prior sensor binary backup is missing or inaccessible: $BIN_BACKUP" >&2
			rollback_failed=1
			restore_complete=0
		fi
	else
		$SUDO rm -f "$BIN_DEST" "$BIN_STAGE" \
			|| { rollback_failed=1; restore_complete=0; }
	fi
  if [ "$INSTALL_SERVICE" = true ] && [ "$restore_complete" = "1" ]; then
    if [ "$OS" = "Darwin" ]; then
      if [ "$WAS_LOADED" = "1" ] && [ "$HAD_CONFIG" = "1" ]; then
        # launchd refuses to load a disabled job. Temporarily enable it, restore
        # its loaded state, then reapply the exact saved disabled state below.
        [ "$LAUNCHD_DISABLED_STATE" != "true" ] \
          || $SUDO launchctl enable system/com.vedetta.sensor >/dev/null 2>&1 \
          || rollback_failed=1
        $SUDO launchctl load "$SERVICE_FILE" >/dev/null 2>&1 || rollback_failed=1
        $SUDO launchctl print system/com.vedetta.sensor >/dev/null 2>&1 || rollback_failed=1
      else
        $SUDO launchctl print system/com.vedetta.sensor >/dev/null 2>&1 && rollback_failed=1
      fi
      case "$LAUNCHD_DISABLED_STATE" in
        true)  $SUDO launchctl disable system/com.vedetta.sensor >/dev/null 2>&1 || rollback_failed=1 ;;
        false) $SUDO launchctl enable system/com.vedetta.sensor >/dev/null 2>&1 || rollback_failed=1 ;;
        unset) : ;;
      esac
    else
      $SUDO systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=1
      if [ "$WAS_RUNNING" = "1" ] && [ "$HAD_CONFIG" = "1" ]; then
        # A mask does not stop an already-running unit, so running+masked is a
        # valid saved state. Temporarily unmask it for restart and restore the
        # mask only after the prior process is live again.
        case "$SYSTEMD_ENABLE_STATE" in
          masked)
            $SUDO systemctl unmask vedetta-sensor >/dev/null 2>&1 || rollback_failed=1
            $SUDO systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=1
            ;;
          masked-runtime)
            $SUDO systemctl unmask --runtime vedetta-sensor >/dev/null 2>&1 || rollback_failed=1
            $SUDO systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=1
            ;;
        esac
        $SUDO systemctl restart vedetta-sensor >/dev/null 2>&1 || rollback_failed=1
        state="$($SUDO systemctl is-active vedetta-sensor 2>/dev/null || true)"
        [ "$state" = "active" ] || rollback_failed=1
      else
        state="$($SUDO systemctl is-active vedetta-sensor 2>/dev/null || true)"
        [ "$state" != "active" ] || rollback_failed=1
      fi
      case "$SYSTEMD_ENABLE_STATE" in
        enabled)
          $SUDO systemctl enable vedetta-sensor >/dev/null 2>&1 || rollback_failed=1
          ;;
        enabled-runtime)
          $SUDO systemctl disable vedetta-sensor >/dev/null 2>&1 || rollback_failed=1
          $SUDO systemctl enable --runtime vedetta-sensor >/dev/null 2>&1 || rollback_failed=1
          ;;
        masked)
          $SUDO systemctl disable vedetta-sensor >/dev/null 2>&1 || true
          $SUDO systemctl mask vedetta-sensor >/dev/null 2>&1 || rollback_failed=1
          ;;
        masked-runtime)
          $SUDO systemctl disable vedetta-sensor >/dev/null 2>&1 || true
          $SUDO systemctl mask --runtime vedetta-sensor >/dev/null 2>&1 || rollback_failed=1
          ;;
        *)
          $SUDO systemctl disable vedetta-sensor >/dev/null 2>&1 || true
          ;;
      esac
    fi
  elif [ "$INSTALL_SERVICE" = true ]; then
    echo "ERROR: prior files were not completely restored; refusing to load or start a sensor from mixed installation state" >&2
    stop_service || rollback_failed=1
  fi
  if [ "$rollback_failed" != "0" ]; then
    PRESERVE_TXN=1
    echo "ERROR: rollback could not restore the complete prior installation; transaction files were preserved for manual recovery" >&2
    [ -z "$BIN_TXN_DIR" ] || echo "       binary transaction: $BIN_TXN_DIR" >&2
    [ -z "$CONFIG_TXN_DIR" ] || echo "       service transaction: $CONFIG_TXN_DIR" >&2
  fi
  set -e
  return "$rollback_failed"
}

cleanup_install() {
  [ "$PRESERVE_TXN" = "0" ] || return 0
  [ -z "$BIN_TXN_DIR" ] || $SUDO rm -rf "$BIN_TXN_DIR" 2>/dev/null || true
  [ -z "$CONFIG_TXN_DIR" ] || $SUDO rm -rf "$CONFIG_TXN_DIR" 2>/dev/null || true
}

on_exit() {
  local rc="$?"
  trap - EXIT
  if [ "$rc" -ne 0 ] && ! rollback_install; then
    echo "ERROR: installation failed and rollback was incomplete" >&2
  fi
  cleanup_install
  cleanup_acquisition
  exit "$rc"
}
trap on_exit EXIT

echo "==> staging installation for ${BIN_DEST}"
ensure_secure_dir "$BIN_DIR" 0755
if [ "$INSTALL_SERVICE" = true ]; then
  validate_root_owned_path "$(dirname "$SERVICE_FILE")"
  validate_root_owned_path "$TOKEN_DIR"
fi
BIN_TXN_DIR="$($SUDO mktemp -d "${BIN_DIR}/.vedetta-install.XXXXXXXX")"
validate_root_owned_path "$BIN_TXN_DIR"
BIN_STAGE="${BIN_TXN_DIR}/candidate"
BIN_BACKUP="${BIN_TXN_DIR}/previous"
if [ "$INSTALL_SERVICE" = true ]; then
  CONFIG_TXN_DIR="$($SUDO mktemp -d "$(dirname "$SERVICE_FILE")/.vedetta-service.XXXXXXXX")"
  validate_root_owned_path "$CONFIG_TXN_DIR"
  CONFIG_STAGE="${CONFIG_TXN_DIR}/candidate"
  CONFIG_BACKUP="${CONFIG_TXN_DIR}/previous"
fi
$SUDO install -m 0755 "$BINARY" "$BIN_STAGE"
validate_root_owned_path "$BIN_STAGE"
binary_runtime_ok "$BIN_STAGE" || die "staged sensor has unresolved shared libraries"
$SUDO env -i PATH="$DAEMON_PATH" VEDETTA_NMAP_PATH="$NMAP_PATH" VEDETTA_SENSOR_TOKEN_FILE="$TOKEN_FILE" "$BIN_STAGE" --version

# A candidate preflight runs before the known-good binary or service is disturbed.
# Fresh enrollment cannot require a token yet; the post-enrollment pass below does.
echo "==> preflight: verifying the staged binary in the service environment"
if [ -z "$ENROLL_CODE" ] && $SUDO test -s "$TOKEN_FILE"; then
  $SUDO env -i PATH="$DAEMON_PATH" VEDETTA_NMAP_PATH="$NMAP_PATH" VEDETTA_SENSOR_TOKEN_FILE="$TOKEN_FILE" \
    "$BIN_STAGE" --check --require-token --core "$CORE_URL" --cidr "$SENSOR_CIDR" \
    || die "staged preflight failed; the existing installation was not changed"
else
  $SUDO env -i PATH="$DAEMON_PATH" VEDETTA_NMAP_PATH="$NMAP_PATH" VEDETTA_SENSOR_TOKEN_FILE="$TOKEN_FILE" \
    "$BIN_STAGE" --check --core "$CORE_URL" --cidr "$SENSOR_CIDR" \
    || die "staged preflight failed; the existing installation was not changed"
fi

if $SUDO test -e "$BIN_DEST" || $SUDO test -L "$BIN_DEST"; then
  $SUDO test -f "$BIN_DEST" && ! $SUDO test -L "$BIN_DEST" \
    || die "sensor binary destination exists but is not a regular, non-symlink file: $BIN_DEST"
  HAD_BINARY=1
fi
if [ "$INSTALL_SERVICE" = true ] \
   && { $SUDO test -e "$SERVICE_FILE" || $SUDO test -L "$SERVICE_FILE"; }; then
  $SUDO test -f "$SERVICE_FILE" && ! $SUDO test -L "$SERVICE_FILE" \
    || die "service definition destination exists but is not a regular, non-symlink file: $SERVICE_FILE"
  HAD_CONFIG=1
fi
if [ "$INSTALL_SERVICE" = true ]; then
  if [ "$OS" = "Darwin" ]; then
    if $SUDO launchctl print system/com.vedetta.sensor >/dev/null 2>&1; then
      WAS_LOADED=1
      pid="$(launchd_pid || true)"
      is_nonzero_pid "$pid" && WAS_RUNNING=1 || true
    fi
    disabled_line="$($SUDO launchctl print-disabled system 2>/dev/null | grep '"com.vedetta.sensor"' || true)"
    case "$disabled_line" in *'=> true'*) LAUNCHD_DISABLED_STATE=true ;; *'=> false'*) LAUNCHD_DISABLED_STATE=false ;; esac
  else
    $SUDO systemctl is-active --quiet vedetta-sensor >/dev/null 2>&1 && WAS_RUNNING=1 || true
    SYSTEMD_ENABLE_STATE="$($SUDO systemctl is-enabled vedetta-sensor 2>/dev/null || true)"
    [ "$SYSTEMD_ENABLE_STATE" = "enabled" ] && WAS_ENABLED=1 || true
  fi
fi

ROLLBACK_ARMED=1
stop_service || die "refusing to replace files while the existing sensor service may still be running"
[ "$HAD_BINARY" = "0" ] || $SUDO mv -f "$BIN_DEST" "$BIN_BACKUP"
[ "$HAD_CONFIG" = "0" ] || $SUDO mv -f "$SERVICE_FILE" "$CONFIG_BACKUP"
$SUDO mv -f "$BIN_STAGE" "$BIN_DEST"
if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
   && [ "${VEDETTA_TEST_FAIL_AFTER_BINARY_MOVE:-0}" = "1" ]; then
	die "synthetic failure after binary promotion"
fi

# Spend the enrollment code through an anonymous pipe into a minimal root
# environment. The secret is never in installer/sudo/sensor argv, a temporary
# pathname, or the service definition. Reset remains one guarded reset+enroll
# attempt, so an invalid/generic code cannot first delete the old token. An
# accidental Core change was rejected before this transaction; the sensor also
# preflights disk replacement and retains idempotent-code recovery.
if [ -n "$ENROLL_CODE" ]; then
  echo "==> enrolling with Core (one-time code, kept out of argv and service configuration)"
  ensure_secure_dir "$TOKEN_DIR" 0700
  reset_mode=0; [ "$RESET" = true ] && reset_mode=1
  sensor_test_log=""
  if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ]; then
    sensor_test_log="${VEDETTA_SENSOR_LOG:-}"
  fi
  printf '%s\n' "$ENROLL_CODE" | $SUDO /bin/sh -c '
    IFS= read -r code || exit 1
    export VEDETTA_ENROLL_CODE="$code"
    export VEDETTA_SENSOR_TOKEN_FILE="$1"
    export VEDETTA_NMAP_PATH="$2"
    [ -z "$6" ] || export VEDETTA_SENSOR_LOG="$6"
    if [ "$5" = "1" ]; then
      exec "$3" --reset --enroll-only --core "$4" --cidr "$7"
    fi
    exec "$3" --enroll-only --core "$4" --cidr "$7"
  ' vedetta-enroll "$TOKEN_FILE" "$NMAP_PATH" "$BIN_DEST" "$CORE_URL" "$reset_mode" "$sensor_test_log" "$SENSOR_CIDR" \
    || die "enrollment failed; restoring the prior installation (check Core and use a bound reset code for an existing sensor)"
fi

if [ "$INSTALL_SERVICE" = true ]; then
  $SUDO test -s "$TOKEN_FILE" || die "enrollment did not leave a non-empty token at $TOKEN_FILE"
  echo "==> preflight: verifying the enrolled credential without changing sensor state"
  $SUDO env -i PATH="$DAEMON_PATH" VEDETTA_NMAP_PATH="$NMAP_PATH" VEDETTA_SENSOR_TOKEN_FILE="$TOKEN_FILE" \
    "$BIN_DEST" --check --require-token --core "$CORE_URL" --cidr "$SENSOR_CIDR" \
    || die "credential preflight failed; restoring the prior installation"
fi

if [ "$INSTALL_SERVICE" != true ]; then
  ROLLBACK_ARMED=0
  echo ""
  echo "==> ✅ binary installed${ENROLL_CODE:+ and enrolled} (service skipped: --no-service)"
  echo "    run it with: sudo env VEDETTA_SENSOR_TOKEN_FILE='$TOKEN_FILE' VEDETTA_NMAP_PATH='$NMAP_PATH' '$BIN_DEST' --core '$CORE_URL' --cidr '$SENSOR_CIDR' --dns"
  exit 0
fi

echo "==> configuring service"
config_value() {
  local label="$1" value="$2"
  if LC_ALL=C printf '%s' "$value" | grep -q '[[:cntrl:]]'; then
    die "$label contains a control character and cannot be written to a service definition"
  fi
}
xml_escape() {
  config_value "plist value" "$1"
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\\&apos;/g"
}
systemd_quote() {
  local value="$1"
  config_value "systemd value" "$value"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//\$/\$\$}"
  value="${value//%/%%}"
  printf '"%s"' "$value"
}
if [ "$OS" = "Darwin" ]; then
  PLIST_BIN="$(xml_escape "$BIN_DEST")"
  PLIST_CORE="$(xml_escape "$CORE_URL")"
  PLIST_CIDR="$(xml_escape "$SENSOR_CIDR")"
  PLIST_PATH="$(xml_escape "$DAEMON_PATH")"
  PLIST_NMAP="$(xml_escape "$NMAP_PATH")"
  PLIST_TOKEN="$(xml_escape "$TOKEN_FILE")"
  PLIST_LOG="$(xml_escape "$SENSOR_LOG")"
  $SUDO tee "$CONFIG_STAGE" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.vedetta.sensor</string>
  <key>ProgramArguments</key><array>
    <string>${PLIST_BIN}</string>
    <string>--core</string><string>${PLIST_CORE}</string>
    <string>--cidr</string><string>${PLIST_CIDR}</string>
    <string>--dns</string>
    <string>--passive-discovery</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>${PLIST_PATH}</string>
    <key>VEDETTA_NMAP_PATH</key><string>${PLIST_NMAP}</string>
    <key>VEDETTA_SENSOR_TOKEN_FILE</key><string>${PLIST_TOKEN}</string>
  </dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${PLIST_LOG}</string>
  <key>StandardErrorPath</key><string>${PLIST_LOG}</string>
</dict></plist>
EOF
  $SUDO chmod 0644 "$CONFIG_STAGE"
  if command -v plutil >/dev/null 2>&1; then
    $SUDO plutil -lint "$CONFIG_STAGE" >/dev/null || die "generated LaunchDaemon plist is invalid"
  fi
		$SUDO mv -f "$CONFIG_STAGE" "$SERVICE_FILE"
		if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
		   && [ "${VEDETTA_TEST_FAIL_AFTER_CONFIG_MOVE:-0}" = "1" ]; then
			die "synthetic failure after service configuration promotion"
		fi
  if $SUDO test -e "$SENSOR_LOG"; then
    $SUDO test -f "$SENSOR_LOG" \
      || die "sensor log exists but is not a regular file: $SENSOR_LOG"
    # Preserve existing diagnostics while tightening an older installation's
    # log permissions. launchd appends the candidate's output to this file.
    $SUDO chmod 0600 "$SENSOR_LOG"
  else
    $SUDO install -m 0600 /dev/null "$SENSOR_LOG"
  fi
  HEALTH_LOG_START="$($SUDO wc -c "$SENSOR_LOG" | awk '{print $1}')"
  case "$HEALTH_LOG_START" in ''|*[!0-9]*) die "could not determine the sensor log offset" ;; esac
  [ "$LAUNCHD_DISABLED_STATE" != "true" ] \
    || $SUDO launchctl enable system/com.vedetta.sensor
  $SUDO launchctl load "$SERVICE_FILE"
  echo "==> installed as a LaunchDaemon"
else
  SD_BIN="$(systemd_quote "$BIN_DEST")"
  SD_CORE="$(systemd_quote "$CORE_URL")"
  SD_CIDR="$(systemd_quote "$SENSOR_CIDR")"
  SD_PATH_ENV="$(systemd_quote "PATH=$DAEMON_PATH")"
  SD_NMAP_ENV="$(systemd_quote "VEDETTA_NMAP_PATH=$NMAP_PATH")"
  SD_TOKEN_ENV="$(systemd_quote "VEDETTA_SENSOR_TOKEN_FILE=$TOKEN_FILE")"
  $SUDO tee "$CONFIG_STAGE" >/dev/null <<EOF
[Unit]
Description=Vedetta Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=${SD_PATH_ENV}
Environment=${SD_NMAP_ENV}
Environment=${SD_TOKEN_ENV}
ExecStartPre=${SD_BIN} --check --require-token --core ${SD_CORE} --cidr ${SD_CIDR}
ExecStart=${SD_BIN} --core ${SD_CORE} --cidr ${SD_CIDR} --dns --passive-discovery
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
  $SUDO chmod 0644 "$CONFIG_STAGE"
	$SUDO mv -f "$CONFIG_STAGE" "$SERVICE_FILE"
	if [ "${VEDETTA_ALLOW_UNSAFE_TEST_PATHS:-0}" = "1" ] \
	   && [ "${VEDETTA_TEST_FAIL_AFTER_CONFIG_MOVE:-0}" = "1" ]; then
		die "synthetic failure after service configuration promotion"
	fi
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable vedetta-sensor
  $SUDO systemctl restart vedetta-sensor
  echo "==> installed as a systemd service"
fi

echo ""
echo "==> waiting for one stable sensor process..."
if ! health_check; then
  echo "!! The new sensor did not remain healthy; it will be stopped and the prior installation restored." >&2
  if [ "$OS" = "Darwin" ]; then
    launchd_log_since_install | tail -n 40 >&2 || true
  else
    $SUDO journalctl -u vedetta-sensor -n 40 --no-pager 2>/dev/null >&2 || true
  fi
  die "post-install health check failed"
fi

ROLLBACK_ARMED=0
echo "==> ✅ Installation complete — one service PID remained stable"
echo "    Logs: sudo tail -f '$SENSOR_LOG'   (or: journalctl -u vedetta-sensor -f)"
echo "    Check: sudo env VEDETTA_SENSOR_TOKEN_FILE='$TOKEN_FILE' VEDETTA_NMAP_PATH='$NMAP_PATH' '$BIN_DEST' --check --require-token --core '$CORE_URL' --cidr '$SENSOR_CIDR'"
