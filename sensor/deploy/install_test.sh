#!/usr/bin/env bash
#
# Installer test for sensor/deploy/install.sh.
#
# Drives install.sh through its macOS (LaunchDaemon) service-configuration path
# in a fully mocked environment — no root, no network, no real binary — and
# asserts the generated plist ProgramArguments. Regression cover for issue #35
# (the macOS LaunchDaemon must carry --enroll-code for the initial registration).
#
# Run: bash sensor/deploy/install_test.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SH="${HERE}/install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
check() { # check <description> <string-that-must-appear> <file>
  if grep -qF -- "$2" "$3"; then
    echo "  ok: $1"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $1 (expected to find: $2)"
    FAIL=$((FAIL + 1))
  fi
}
refute() { # refute <description> <string-that-must-NOT-appear> <file>
  if grep -qF -- "$2" "$3"; then
    echo "  FAIL: $1 (did not expect: $2)"
    FAIL=$((FAIL + 1))
  else
    echo "  ok: $1"
    PASS=$((PASS + 1))
  fi
}

# --- Mock environment: uname=Darwin, no-op sudo/launchctl, present nmap. ------
MOCKBIN="${WORK}/bin"
mkdir -p "$MOCKBIN"

cat >"${MOCKBIN}/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -s) echo Darwin ;;
  -m) echo arm64 ;;
  *)  echo Darwin ;;
esac
EOF

cat >"${MOCKBIN}/sudo" <<'EOF'
#!/usr/bin/env bash
exec "$@"
EOF

# launchctl / nmap: no-ops (nmap present => ensure_nmap short-circuits, no brew).
printf '#!/usr/bin/env bash\nexit 0\n' >"${MOCKBIN}/launchctl"
printf '#!/usr/bin/env bash\nexit 0\n' >"${MOCKBIN}/nmap"

# Fake sensor binary the installer will "install" and probe with --version.
cat >"${MOCKBIN}/fake-vedetta-sensor" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "--version" ] && echo "vedetta-sensor test"
exit 0
EOF
chmod +x "${MOCKBIN}"/*

run_installer() { # run_installer <plist-out> [extra install.sh args...]
  local plist="$1"; shift
  PATH="${MOCKBIN}:${PATH}" \
  VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
  VEDETTA_BIN_DIR="${WORK}/prefix" \
  VEDETTA_PLIST_PATH="$plist" \
    bash "$INSTALL_SH" "$@" >"${plist}.log" 2>&1
}

# --- Case 1: enrollment code supplied -> plist MUST carry --enroll-code. ------
echo "case: macOS install WITH --enroll-code"
PLIST1="${WORK}/with-code.plist"
run_installer "$PLIST1" --core http://198.51.100.10:8080 --enroll-code ENROLL-TEST-123
check "plist references --core"            "--core"                      "$PLIST1"
check "plist carries core URL"             "http://198.51.100.10:8080"   "$PLIST1"
check "plist references --enroll-code"      "--enroll-code"               "$PLIST1"
check "plist carries the enrollment code"  "ENROLL-TEST-123"             "$PLIST1"
check "plist keeps --cidr auto"            "--cidr"                       "$PLIST1"
check "plist enables --dns"                "--dns"                        "$PLIST1"
check "plist enables --passive-discovery"  "--passive-discovery"         "$PLIST1"

# --- Case 2: no enrollment code -> plist MUST NOT carry --enroll-code. --------
echo "case: macOS install WITHOUT --enroll-code"
PLIST2="${WORK}/no-code.plist"
run_installer "$PLIST2" --core http://198.51.100.10:8080
check  "plist references --core"           "--core"                      "$PLIST2"
refute "plist omits --enroll-code"         "--enroll-code"               "$PLIST2"
check  "plist still enables --dns"         "--dns"                       "$PLIST2"

# --- Case 3: brew must NEVER run as root (issue #45). ------------------------
# Simulate running under sudo (id -u == 0, SUDO_USER set) on macOS with nmap
# ABSENT so ensure_nmap must install it via Homebrew. Assert brew is invoked as
# the invoking user through `sudo -u`, never directly as root.
echo "case: macOS brew dependency install does not run brew as root"
BREWROOT="${WORK}/brewroot"
mkdir -p "$BREWROOT/bin"
SUDO_LOG="${BREWROOT}/sudo.log"
BREW_LOG="${BREWROOT}/brew.log"

# id: pretend we are root.
cat >"${BREWROOT}/bin/id" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "-u" ] && { echo 0; exit 0; }
echo 0
EOF

# uname: Darwin/arm64 (same as the other cases).
cp "${MOCKBIN}/uname" "${BREWROOT}/bin/uname"

# sudo: log every invocation, then exec the remainder (handles `-u <user> cmd`).
cat >"${BREWROOT}/bin/sudo" <<EOF
#!/usr/bin/env bash
echo "\$@" >>"${SUDO_LOG}"
if [ "\${1:-}" = "-u" ]; then shift 2; fi
exec "\$@"
EOF

# brew: record args; \`list\` reports "not installed" so \`install\` runs.
cat >"${BREWROOT}/bin/brew" <<EOF
#!/usr/bin/env bash
echo "\$@" >>"${BREW_LOG}"
[ "\${1:-}" = "list" ] && exit 1
exit 0
EOF

# launchctl no-op (no nmap mock here => ensure_nmap must reach brew).
printf '#!/usr/bin/env bash\nexit 0\n' >"${BREWROOT}/bin/launchctl"
chmod +x "${BREWROOT}/bin/"*

PLIST3="${WORK}/brew-root.plist"
# Constrained PATH: BREWROOT mocks + core utils only. Deliberately EXCLUDES
# ${MOCKBIN} (its nmap stub would short-circuit ensure_nmap) and the host's real
# nmap, so ensure_nmap must install it via brew. The fake sensor binary is passed
# by absolute path via VEDETTA_SENSOR_BINARY, so it needs no PATH entry.
PATH="${BREWROOT}/bin:/usr/bin:/bin" \
SUDO_USER="operator" \
VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
VEDETTA_BIN_DIR="${WORK}/prefix3" \
VEDETTA_PLIST_PATH="$PLIST3" \
  bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${PLIST3}.log" 2>&1 || true

check  "brew was invoked (nmap install attempted)" "install" "$BREW_LOG"
check  "brew ran via 'sudo -u operator'"           "-u operator" "$SUDO_LOG"
# The brew invocation logged by sudo must carry the invoking user, proving brew
# was not exec'd directly as root.
if grep -E -- '-u operator .*brew (list|install)' "$SUDO_LOG" >/dev/null; then
  echo "  ok: brew dependency command dropped to the invoking user"
  PASS=$((PASS + 1))
else
  echo "  FAIL: brew was not run as the invoking user via sudo -u"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "installer test: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
