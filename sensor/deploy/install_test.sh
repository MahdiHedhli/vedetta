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

echo ""
echo "installer test: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
