#!/usr/bin/env bash
#
# Installer test for sensor/deploy/install.sh.
#
# Drives install.sh through its macOS (LaunchDaemon) service-configuration path
# in a fully mocked environment — no root, no network, no real binary — and
# asserts the generated plist ProgramArguments. Regression cover for issue #35:
# the enrollment code must be spent in a one-shot --enroll-only step (via the
# environment) and must NEVER land in the LaunchDaemon config, which any local
# user can read. The service authenticates with the persisted token instead.
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
# Pass-through mock: skip sudo's own options (-E, -H, -n, -u <user>, --flags), then exec
# the command. Runs in-process so the caller's exported env (e.g. VEDETTA_ENROLL_CODE) is
# inherited, mirroring `sudo -E`.
while [ $# -gt 0 ]; do
  case "$1" in
    -u) shift 2 ;;
    -*) shift ;;
    *)  break ;;
  esac
done
exec "$@"
EOF

# launchctl / nmap: no-ops (nmap present => ensure_nmap short-circuits, no brew).
printf '#!/usr/bin/env bash\nexit 0\n' >"${MOCKBIN}/launchctl"
printf '#!/usr/bin/env bash\nexit 0\n' >"${MOCKBIN}/nmap"

# Fake sensor binary the installer will "install" and probe with --version.
# It also records every invocation (argv + whether the enroll code arrived via ENV)
# so the tests can prove enrollment happened out-of-band and the code never reached a
# command line. On --enroll-only it persists a token at the pinned path, mirroring a
# real successful enrollment so the follow-on service config can be created code-free.
cat >"${MOCKBIN}/fake-vedetta-sensor" <<'EOF'
#!/usr/bin/env bash
if [ -n "${VEDETTA_SENSOR_LOG:-}" ]; then
  printf 'argv=[%s] enrollcode_env=%s\n' "$*" "${VEDETTA_ENROLL_CODE:-<unset>}" >>"$VEDETTA_SENSOR_LOG"
fi
case "${1:-}" in
  --version) echo "vedetta-sensor test" ;;
  --enroll-only)
    if [ -n "${VEDETTA_SENSOR_TOKEN_FILE:-}" ]; then
      mkdir -p "$(dirname "$VEDETTA_SENSOR_TOKEN_FILE")"
      printf 'fake-enrolled-token' >"$VEDETTA_SENSOR_TOKEN_FILE"
    fi
    ;;
esac
exit 0
EOF
chmod +x "${MOCKBIN}"/*

run_installer() { # run_installer <plist-out> [extra install.sh args...]
  local plist="$1"; shift
  # Pin the token path (per-plist) so the installer's enroll step and the fake binary
  # agree, and give the binary a log to record how it was invoked.
  PATH="${MOCKBIN}:${PATH}" \
  VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
  VEDETTA_BIN_DIR="${WORK}/prefix" \
  VEDETTA_PLIST_PATH="$plist" \
  VEDETTA_SENSOR_TOKEN_FILE="${plist}.token" \
  VEDETTA_SENSOR_LOG="${plist}.senslog" \
    bash "$INSTALL_SH" "$@" >"${plist}.log" 2>&1
}

# --- Case 1: enrollment code supplied -> spent in a one-shot --enroll-only step
#     (code via ENV), then the plist is written WITHOUT the code. ---------------
echo "case: macOS install WITH --enroll-code"
PLIST1="${WORK}/with-code.plist"
run_installer "$PLIST1" --core http://198.51.100.10:8080 --enroll-code ENROLL-TEST-123
check  "plist references --core"           "--core"                      "$PLIST1"
check  "plist carries core URL"            "http://198.51.100.10:8080"   "$PLIST1"
refute "plist omits the --enroll-code flag" "--enroll-code"              "$PLIST1"
refute "plist omits the enrollment code"    "ENROLL-TEST-123"            "$PLIST1"
check  "plist keeps --cidr auto"           "--cidr"                      "$PLIST1"
check  "plist enables --dns"               "--dns"                       "$PLIST1"
check  "plist enables --passive-discovery" "--passive-discovery"         "$PLIST1"
check  "plist carries the token-file env"  "VEDETTA_SENSOR_TOKEN_FILE"   "$PLIST1"
# The one-shot enrollment must have run, with the code supplied via ENV — never argv.
check  "sensor was enrolled out-of-band"   "argv=[--enroll-only"         "${PLIST1}.senslog"
check  "code was passed via environment"   "enrollcode_env=ENROLL-TEST-123" "${PLIST1}.senslog"
if grep -E 'argv=\[[^]]*ENROLL-TEST-123' "${PLIST1}.senslog" >/dev/null 2>&1; then
  echo "  FAIL: enrollment code appeared on a command line (argv)"
  FAIL=$((FAIL + 1))
else
  echo "  ok: enrollment code never appeared on a command line"
  PASS=$((PASS + 1))
fi

# --- Case 2: no code but an existing token -> update path. Service re-created
#     code-free; no fresh enrollment attempted. --------------------------------
echo "case: macOS re-install WITHOUT --enroll-code (already enrolled)"
PLIST2="${WORK}/no-code.plist"
printf 'already-enrolled-token' >"${PLIST2}.token"   # simulate a prior enrollment
run_installer "$PLIST2" --core http://198.51.100.10:8080
check  "plist references --core"           "--core"                      "$PLIST2"
refute "plist omits --enroll-code"         "--enroll-code"               "$PLIST2"
check  "plist still enables --dns"         "--dns"                       "$PLIST2"
check  "plist carries the token-file env"  "VEDETTA_SENSOR_TOKEN_FILE"   "$PLIST2"
refute "no re-enrollment on update path"   "argv=[--enroll-only"         "${PLIST2}.senslog"

# --- Case 2b: fresh install, no code, no token -> must refuse (fail closed). --
echo "case: macOS fresh install WITHOUT code or token -> refused"
PLIST2B="${WORK}/fresh-no-code.plist"
if run_installer "$PLIST2B" --core http://198.51.100.10:8080; then
  echo "  FAIL: installer configured a service with neither a code nor a token"
  FAIL=$((FAIL + 1))
else
  echo "  ok: installer refused a code-less fresh install"
  PASS=$((PASS + 1))
fi
if [ -f "$PLIST2B" ]; then
  echo "  FAIL: a service plist was written despite the refusal"
  FAIL=$((FAIL + 1))
else
  echo "  ok: no service plist written on refusal"
  PASS=$((PASS + 1))
fi

# --- Case 4: Linux systemd path — the enrollment code must stay out of the
#     systemd unit too (parity with the launchd path). --------------------------
echo "case: Linux install WITH --enroll-code (systemd unit)"
LINUXBIN="${WORK}/linuxbin"
mkdir -p "$LINUXBIN"
cat >"${LINUXBIN}/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *)  echo Linux ;;
esac
EOF
printf '#!/usr/bin/env bash\nexit 0\n' >"${LINUXBIN}/systemctl"
chmod +x "${LINUXBIN}"/*

UNIT4="${WORK}/vedetta-sensor.service"
# Linux uname mock shadows the Darwin one; reuse the shared sudo/nmap/fake binary.
PATH="${LINUXBIN}:${MOCKBIN}:${PATH}" \
VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
VEDETTA_BIN_DIR="${WORK}/prefix4" \
VEDETTA_SERVICE_PATH="$UNIT4" \
VEDETTA_SENSOR_TOKEN_FILE="${UNIT4}.token" \
VEDETTA_SENSOR_LOG="${UNIT4}.senslog" \
  bash "$INSTALL_SH" --core http://198.51.100.10:8080 --enroll-code ENROLL-TEST-456 >"${UNIT4}.log" 2>&1

check  "unit references --core"            "--core"                      "$UNIT4"
check  "unit carries core URL"             "http://198.51.100.10:8080"   "$UNIT4"
refute "unit omits the --enroll-code flag" "--enroll-code"               "$UNIT4"
refute "unit omits the enrollment code"    "ENROLL-TEST-456"             "$UNIT4"
check  "unit enables --passive-discovery"  "--passive-discovery"         "$UNIT4"
check  "unit carries the token-file env"   "VEDETTA_SENSOR_TOKEN_FILE"   "$UNIT4"
check  "sensor was enrolled out-of-band"   "argv=[--enroll-only"         "${UNIT4}.senslog"
check  "code was passed via environment"   "enrollcode_env=ENROLL-TEST-456" "${UNIT4}.senslog"
if grep -E 'argv=\[[^]]*ENROLL-TEST-456' "${UNIT4}.senslog" >/dev/null 2>&1; then
  echo "  FAIL: enrollment code appeared on a command line (argv)"
  FAIL=$((FAIL + 1))
else
  echo "  ok: enrollment code never appeared on a command line"
  PASS=$((PASS + 1))
fi

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
