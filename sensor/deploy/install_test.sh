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
WORK_PHYSICAL="$(cd "$WORK" && pwd -P)"
SECRET_WORK="$(mktemp -d "${HOME}/.vedetta-secret-test.XXXXXXXX")"
cleanup() {
  local rc="$?"
  if [ "$rc" -ne 0 ]; then
    for f in "$WORK"/*.log "$WORK"/rollback/*.log "$WORK"/linux-rollback/*.log; do
      [ -f "$f" ] || continue
      echo "--- $f" >&2
      sed -n '1,200p' "$f" >&2
    done
    if [ -n "${SYSTEMD_COMMANDS:-}" ] && [ -f "$SYSTEMD_COMMANDS" ]; then
      echo "--- $SYSTEMD_COMMANDS" >&2
      sed -n '1,240p' "$SYSTEMD_COMMANDS" >&2
    fi
  fi
  if [ "${VEDETTA_TEST_KEEP_WORK:-0}" = "1" ]; then
    echo "installer test work preserved at $WORK" >&2
    echo "installer secret-test work preserved at $SECRET_WORK" >&2
    exit "$rc"
  fi
  rm -rf "$WORK"
  rm -rf "$SECRET_WORK"
  exit "$rc"
}
trap cleanup EXIT

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
  if grep -qF -- "$2" "$3" 2>/dev/null; then
    echo "  FAIL: $1 (did not expect: $2)"
    FAIL=$((FAIL + 1))
  else
    echo "  ok: $1"
    PASS=$((PASS + 1))
  fi
}

inode_of() {
  if [ "$(/usr/bin/uname -s)" = "Darwin" ]; then
    /usr/bin/stat -f '%i' "$1"
  else
    /usr/bin/stat -c '%i' "$1"
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
[ "$#" -gt 0 ] || exit 0
exec "$@"
EOF

# Stateful launchctl: enough fidelity to prove stop verification and rollback.
LAUNCHD_STATE="${WORK}/launchd.state"
LAUNCHD_DISABLED_STATE_FILE="${WORK}/launchd.disabled"
LAUNCHD_COMMANDS="${WORK}/launchd.commands"
printf 'absent\n' >"$LAUNCHD_STATE"
printf 'false\n' >"$LAUNCHD_DISABLED_STATE_FILE"
: >"$LAUNCHD_COMMANDS"
cat >"${MOCKBIN}/launchctl" <<EOF
#!/usr/bin/env bash
state="$LAUNCHD_STATE"
disabled_state="$LAUNCHD_DISABLED_STATE_FILE"
printf '%s\n' "\$*" >>"$LAUNCHD_COMMANDS"
case "\${1:-}" in
  print-disabled) printf '    "com.vedetta.sensor" => %s\n' "\$(cat "\$disabled_state")" ;;
  print)
    case "\$(cat "\$state")" in loaded|sticky) ;; *) exit 113 ;; esac
    printf 'state = running\n    pid = 401\n'
    ;;
  bootout|unload)
    [ "\$(cat "\$state")" != sticky ] || exit 1
    printf 'absent\n' >"\$state"
    ;;
  load|bootstrap)
    [ "\$(cat "\$disabled_state")" != true ] || exit 1
    printf 'loaded\n' >"\$state"
    ;;
  enable) printf 'false\n' >"\$disabled_state" ;;
  disable) printf 'true\n' >"\$disabled_state" ;;
  *) : ;;
esac
EOF
# nmap is present => ensure_nmap short-circuits, no brew.
printf '#!/usr/bin/env bash\nexit 0\n' >"${MOCKBIN}/nmap"

# Fake sensor binary the installer will "install" and probe with --version.
# It also records every invocation (argv + whether the enroll code arrived via ENV)
# so the tests can prove enrollment happened out-of-band and the code never reached a
# command line. On --enroll-only it persists a token at the pinned path, mirroring a
# real successful enrollment so the follow-on service config can be created code-free.
cat >"${MOCKBIN}/fake-vedetta-sensor" <<'EOF'
#!/usr/bin/env bash
printf 'sensor-argv=[%s]\n' "$*"
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

echo "case: production installer rejects token-path override"
TOKEN_OVERRIDE_LOG="${WORK}/token-override.log"
if VEDETTA_ALLOW_UNSAFE_TEST_PATHS=0 VEDETTA_SENSOR_TOKEN_FILE=/etc/passwd \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 --no-service >"$TOKEN_OVERRIDE_LOG" 2>&1; then
  echo "  FAIL: production token-path override was accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: production token-path override rejected"
  PASS=$((PASS + 1))
fi
check "override rejection identifies test-only variable" "VEDETTA_SENSOR_TOKEN_FILE is test-only" "$TOKEN_OVERRIDE_LOG"

run_installer() { # run_installer <plist-out> [extra install.sh args...]
  local plist="$1"; shift
  printf '%s\n' "${RUN_INSTALLER_LAUNCHD_STATE:-absent}" >"$LAUNCHD_STATE"
  printf '%s\n' "${RUN_INSTALLER_LAUNCHD_DISABLED_STATE:-false}" >"$LAUNCHD_DISABLED_STATE_FILE"
  : >"$LAUNCHD_COMMANDS"
  # Pin the token path (per-plist) so the installer's enroll step and the fake binary
  # agree, and give the binary a log to record how it was invoked.
  # VEDETTA_SKIP_HEALTHCHECK: no real service manager in the mock, so skip the
  # post-install daemon-liveness poll (the plist/preflight assertions are what matter).
  PATH="${MOCKBIN}:${PATH}" \
  VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
  VEDETTA_BIN_DIR="${WORK}/prefix" \
  VEDETTA_PLIST_PATH="$plist" \
  VEDETTA_SENSOR_TOKEN_FILE="${plist}.token" \
  VEDETTA_SENSOR_LOG="${plist}.senslog" \
  VEDETTA_SENSOR_LOG_FILE="${plist}.daemon.log" \
  VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
  VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
  VEDETTA_TEST_OS=Darwin \
  VEDETTA_TEST_ARCH=arm64 \
  VEDETTA_SKIP_HEALTHCHECK=1 \
    bash "$INSTALL_SH" "$@" >"${plist}.log" 2>&1
}

code_file() { # code_file <name> <secret>
  local path="${WORK}/$1.code"
  printf '%s\n' "$2" >"$path"
  chmod 0600 "$path"
  printf '%s' "$path"
}

write_launchd_service() { # write_launchd_service <path> <XML-encoded-core> <marker>
  local path="$1" core="$2" marker="$3"
  cat >"$path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.vedetta.sensor</string>
  <key>ProgramArguments</key><array>
    <string>/Library/Vedetta/bin/vedetta-sensor</string>
    <string>--core</string><string>${core}</string>
    <string>--cidr</string><string>auto</string>
    <string>--dns</string>
    <string>--passive-discovery</string>
  </array>
  <key>TestMarker</key><string>${marker}</string>
</dict></plist>
EOF
}

write_systemd_service() { # write_systemd_service <path> <encoded-core> <marker>
  local path="$1" core="$2" marker="$3"
  cat >"$path" <<EOF
[Unit]
Description=Vedetta Sensor (${marker})
[Service]
ExecStart="/usr/local/libexec/vedetta/vedetta-sensor" --core "${core}" --cidr "auto" --dns --passive-discovery
EOF
}

# The compatibility flag is fail-closed: the installer itself must never carry
# the secret in its process argv unless an operator opts into the deprecated risk.
echo "case: legacy argv secret is rejected by default"
PLIST_LEGACY="${WORK}/legacy.plist"
if run_installer "$PLIST_LEGACY" --core http://198.51.100.10:8080 --enroll-code SHOULD-NOT-BE-IN-ARGV; then
  echo "  FAIL: legacy argv secret was accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: legacy argv secret rejected"
  PASS=$((PASS + 1))
fi
check "rejection explains secure inputs" "--enroll-code-file" "${PLIST_LEGACY}.log"

echo "case: enrollment code via stdin"
PLIST_STDIN="${WORK}/stdin.plist"
printf '%s\n' STDIN-TEST-123 | run_installer "$PLIST_STDIN" --core http://198.51.100.10:8080 --enroll-code-stdin
check "stdin secret reached enrollment environment" "enrollcode_env=STDIN-TEST-123" "${PLIST_STDIN}.senslog"
if grep -E 'argv=\[[^]]*STDIN-TEST-123' "${PLIST_STDIN}.senslog" >/dev/null 2>&1; then
  echo "  FAIL: stdin secret appeared in sensor argv"
  FAIL=$((FAIL + 1))
else
  echo "  ok: stdin secret absent from sensor argv"
  PASS=$((PASS + 1))
fi

echo "case: insecure enrollment-code file mode is rejected"
printf 'absent\n' >"$LAUNCHD_STATE"
: >"$LAUNCHD_COMMANDS"
BAD_CODE="${SECRET_WORK}/bad-mode.code"
printf '%s\n' BAD-MODE-123 >"$BAD_CODE"
chmod 0644 "$BAD_CODE"
BAD_LOG="${WORK}/bad-mode.log"
SECRET_TEST_OS="$(/usr/bin/uname -s)"
if PATH="${MOCKBIN}:${PATH}" \
   VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 VEDETTA_TEST_ENFORCE_SECRET_VALIDATION=1 \
   VEDETTA_TEST_OS="$SECRET_TEST_OS" VEDETTA_TEST_ARCH=amd64 \
   VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" VEDETTA_BIN_DIR="${WORK}/bad-prefix" \
   VEDETTA_PLIST_PATH="${WORK}/bad-mode.plist" VEDETTA_SERVICE_PATH="${WORK}/bad-mode.service" \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 --no-service --enroll-code-file "$BAD_CODE" >"$BAD_LOG" 2>&1; then
  echo "  FAIL: group/world-readable code file accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: group/world-readable code file rejected"
  PASS=$((PASS + 1))
fi
check "bad mode remediation is explicit" "chmod 600" "$BAD_LOG"

echo "case: plist values are XML encoded and custom CIDR persists"
PLIST_ESC="${WORK}/escaped.plist"
CODE_ESC="$(code_file escape ESCAPE-TEST-123)"
run_installer "$PLIST_ESC" --core 'https://example.test/a&b/%22q%22' --cidr 192.0.2.0/24 --enroll-code-file "$CODE_ESC"
check "plist encodes URL ampersand" 'https://example.test/a&amp;b/%22q%22' "$PLIST_ESC"
check "plist persists requested CIDR" '192.0.2.0/24' "$PLIST_ESC"

# --- Case 1: enrollment code supplied -> spent in a one-shot --enroll-only step
#     (code via ENV), then the plist is written WITHOUT the code. ---------------
echo "case: macOS install WITH --enroll-code-file"
PLIST1="${WORK}/with-code.plist"
CODE1="$(code_file enroll ENROLL-TEST-123)"
run_installer "$PLIST1" --core http://198.51.100.10:8080 --enroll-code-file "$CODE1"
check  "plist references --core"           "--core"                      "$PLIST1"
check  "plist carries core URL"            "http://198.51.100.10:8080"   "$PLIST1"
refute "plist omits the --enroll-code flag" "--enroll-code"              "$PLIST1"
refute "plist omits the enrollment code"    "ENROLL-TEST-123"            "$PLIST1"
check  "plist keeps --cidr auto"           "--cidr"                      "$PLIST1"
check  "plist enables --dns"               "--dns"                       "$PLIST1"
check  "plist enables --passive-discovery" "--passive-discovery"         "$PLIST1"
check  "plist carries the token-file env"  "VEDETTA_SENSOR_TOKEN_FILE"   "$PLIST1"
# The daemon must be given a PATH that can resolve nmap (the launchd-minimal-PATH fix).
check  "plist bakes a service PATH"        "<key>PATH</key>"             "$PLIST1"
check  "service PATH keeps the system dirs" "/usr/bin:/bin:/usr/sbin:/sbin" "$PLIST1"
refute "service PATH excludes Homebrew"     "/opt/homebrew/bin:/usr"      "$PLIST1"
check  "plist pins absolute nmap"           "VEDETTA_NMAP_PATH"           "$PLIST1"
# The one-shot enrollment must have run, with the code supplied via ENV — never argv.
check  "sensor was enrolled out-of-band"   "argv=[--enroll-only"         "${PLIST1}.senslog"
check  "code was passed via environment"   "enrollcode_env=ENROLL-TEST-123" "${PLIST1}.senslog"
check  "staged preflight ran"              "preflight: verifying the staged binary" "${PLIST1}.log"
if grep -E 'argv=\[[^]]*ENROLL-TEST-123' "${PLIST1}.senslog" >/dev/null 2>&1; then
  echo "  FAIL: enrollment code appeared on a command line (argv)"
  FAIL=$((FAIL + 1))
else
  echo "  ok: enrollment code never appeared on a command line"
  PASS=$((PASS + 1))
fi

# --- Reset is one guarded reset+enroll invocation. It must not run the old
#     destructive bare --reset step before validating the bound code. -----------
echo "case: macOS reset uses one guarded attempt"
PLISTR="${WORK}/reset.plist"
printf 'existing-token' >"${PLISTR}.token"
CODER="$(code_file reset RESET-TEST-123)"
run_installer "$PLISTR" --core http://198.51.100.10:8080 --reset --enroll-code-file "$CODER"
check "reset and enrollment share one process" "argv=[--reset --enroll-only" "${PLISTR}.senslog"
RESET_FIRST_CHECK="$(grep '^sensor-argv=\[--check' "${PLISTR}.log" | head -1)"
if printf '%s' "$RESET_FIRST_CHECK" | grep -q -- '--require-token'; then
  echo "  FAIL: reset preflight tried to validate the obsolete/revoked bearer"
  FAIL=$((FAIL + 1))
else
  echo "  ok: reset preflight omits --require-token for the obsolete bearer"
  PASS=$((PASS + 1))
fi
if [ "$(grep -cF 'argv=[--reset' "${PLISTR}.senslog")" -eq 1 ]; then
  echo "  ok: no separate destructive reset invocation"
  PASS=$((PASS + 1))
else
  echo "  FAIL: reset was invoked more than once"
  FAIL=$((FAIL + 1))
fi

echo "case: hostless Core URL is rejected before mutation"
HOSTLESS_LOG="${WORK}/hostless.log"
if PATH="${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 \
     bash "$INSTALL_SH" --core http:// --no-service >"$HOSTLESS_LOG" 2>&1; then
  echo "  FAIL: hostless Core URL accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: hostless Core URL rejected"
  PASS=$((PASS + 1))
fi
check "hostless URL error names missing host" "hostname or IP address" "$HOSTLESS_LOG"

EARLY_HIJACK="${WORK}/early-path-hijack"
mkdir -p "$EARLY_HIJACK"
cat >"${EARLY_HIJACK}/grep" <<EOF
#!/bin/sh
touch "${WORK}/early-path-executed"
exec /usr/bin/grep "\$@"
EOF
chmod +x "${EARLY_HIJACK}/grep"
if PATH="${EARLY_HIJACK}:${PATH}" bash "$INSTALL_SH" --core http:// --no-service >/dev/null 2>&1; then
  echo "  FAIL: production-path hostless invocation unexpectedly succeeded"
  FAIL=$((FAIL + 1))
elif [ -e "${WORK}/early-path-executed" ]; then
  echo "  FAIL: installer executed an invoking-user PATH utility before sanitizing PATH"
  FAIL=$((FAIL + 1))
else
  echo "  ok: installer sanitizes PATH before its first external utility"
  PASS=$((PASS + 1))
fi

echo "case: unsafe Core URL components are rejected before mutation"
for unsafe_core in 'https://user:secret@example.test' 'https://example.test/path?redirect=1' 'https://example.test/path#fragment'; do
  UNSAFE_CORE_LOG="${WORK}/unsafe-core-${PASS}-${FAIL}.log"
  if PATH="${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 \
       bash "$INSTALL_SH" --core "$unsafe_core" --no-service >"$UNSAFE_CORE_LOG" 2>&1; then
    echo "  FAIL: unsafe Core URL accepted"
    FAIL=$((FAIL + 1))
  else
    echo "  ok: unsafe Core URL rejected"
    PASS=$((PASS + 1))
  fi
done

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

echo "case: macOS existing Core comparison accepts normalized equivalent"
PLIST_CORE_EQ="${WORK}/core-equivalent.plist"
write_launchd_service "$PLIST_CORE_EQ" 'HTTP://CORE.Example.Test/Proxy&amp;quot;/&quot;/&apos;/&lt;&gt;/&amp;///' core-equivalent-old
printf 'equivalent-token' >"${PLIST_CORE_EQ}.token"
CORE_EQ_REQUEST="http://core.example.test/Proxy&quot;/\"/'/<>/&"
if VEDETTA_TEST_FORCE_PLIST_FALLBACK=1 run_installer "$PLIST_CORE_EQ" --core "$CORE_EQ_REQUEST"; then
  echo "  ok: LaunchDaemon authority case and trailing slash differences accepted"
  PASS=$((PASS + 1))
else
  echo "  FAIL: normalized-equivalent LaunchDaemon Core URL rejected"
  FAIL=$((FAIL + 1))
fi
check "single-pass XML entities round-trip on LaunchDaemon update" 'Proxy&amp;quot;/&quot;/&apos;/&lt;&gt;/&amp;' "$PLIST_CORE_EQ"

echo "case: macOS changed Core is rejected before stop or enrollment"
PLIST_CORE_CHANGED="${WORK}/core-changed.plist"
write_launchd_service "$PLIST_CORE_CHANGED" 'https://core.example.test/Router' core-change-blocked
printf 'unchanged-launchd-token' >"${PLIST_CORE_CHANGED}.token"
CODE_CORE_CHANGED="$(code_file core-changed RESET-CORE-CHANGE)"
if RUN_INSTALLER_LAUNCHD_STATE=loaded run_installer "$PLIST_CORE_CHANGED" --core 'https://core.example.test/router' --reset --enroll-code-file "$CODE_CORE_CHANGED"; then
  echo "  FAIL: path-case Core change was accepted for a LaunchDaemon"
  FAIL=$((FAIL + 1))
else
  echo "  ok: path-case Core change rejected for a LaunchDaemon"
  PASS=$((PASS + 1))
fi
check "LaunchDaemon Core-change error explains credential migration" "credential migration" "${PLIST_CORE_CHANGED}.log"
check "rejected LaunchDaemon config stayed intact" "core-change-blocked" "$PLIST_CORE_CHANGED"
check "rejected LaunchDaemon token stayed intact" "unchanged-launchd-token" "${PLIST_CORE_CHANGED}.token"
check "rejected LaunchDaemon stayed loaded" "loaded" "$LAUNCHD_STATE"
refute "rejected LaunchDaemon update never requested stop" "bootout" "$LAUNCHD_COMMANDS"
refute "rejected LaunchDaemon update never enrolled" "argv=[--reset --enroll-only" "${PLIST_CORE_CHANGED}.senslog"

echo "case: LaunchDaemon duplicate Core options are rejected"
for parser_mode in native fallback; do
  PLIST_CORE_OVERRIDE="${WORK}/core-override-${parser_mode}.plist"
  write_launchd_service "$PLIST_CORE_OVERRIDE" 'http://198.51.100.10:8080' duplicate-core-blocked
  sed 's#  </array>#    <string>--core=http://203.0.113.9:8080</string>\
  </array>#' "$PLIST_CORE_OVERRIDE" >"${PLIST_CORE_OVERRIDE}.new"
  mv "${PLIST_CORE_OVERRIDE}.new" "$PLIST_CORE_OVERRIDE"
  printf 'unchanged-duplicate-token' >"${PLIST_CORE_OVERRIDE}.token"
  CODE_CORE_OVERRIDE="$(code_file "core-override-${parser_mode}" RESET-DUPLICATE-CORE)"
  if [ "$parser_mode" = fallback ]; then
    parser_env=1
  else
    parser_env=0
  fi
  if VEDETTA_TEST_FORCE_PLIST_FALLBACK="$parser_env" RUN_INSTALLER_LAUNCHD_STATE=loaded \
       run_installer "$PLIST_CORE_OVERRIDE" --core http://198.51.100.10:8080 \
       --reset --enroll-code-file "$CODE_CORE_OVERRIDE"; then
    echo "  FAIL: ambiguous LaunchDaemon was accepted by $parser_mode parser"
    FAIL=$((FAIL + 1))
  else
    echo "  ok: ambiguous LaunchDaemon refused by $parser_mode parser"
    PASS=$((PASS + 1))
  fi
  check "duplicate LaunchDaemon config stayed intact ($parser_mode)" "duplicate-core-blocked" "$PLIST_CORE_OVERRIDE"
  check "duplicate LaunchDaemon token stayed intact ($parser_mode)" "unchanged-duplicate-token" "${PLIST_CORE_OVERRIDE}.token"
  check "duplicate LaunchDaemon stayed loaded ($parser_mode)" "loaded" "$LAUNCHD_STATE"
  refute "duplicate LaunchDaemon was not stopped ($parser_mode)" "bootout" "$LAUNCHD_COMMANDS"
  refute "duplicate LaunchDaemon never enrolled ($parser_mode)" "argv=[--reset --enroll-only" "${PLIST_CORE_OVERRIDE}.senslog"
done

echo "case: macOS --no-service refuses an existing managed service before reading its code"
PLIST_NO_SERVICE="${WORK}/no-service-existing.plist"
write_launchd_service "$PLIST_NO_SERVICE" 'http://198.51.100.10:8080' no-service-config
printf 'no-service-token' >"${PLIST_NO_SERVICE}.token"
mkdir -p "${WORK}/prefix"
printf '#!/usr/bin/env bash\necho no-service-binary\n' >"${WORK}/prefix/vedetta-sensor"
chmod +x "${WORK}/prefix/vedetta-sensor"
CODE_NO_SERVICE="${WORK}/no-service.code"
printf 'NO-SERVICE-CODE' >"$CODE_NO_SERVICE"
chmod 0644 "$CODE_NO_SERVICE" # Would be rejected if read_enrollment_secret ran first.
if RUN_INSTALLER_LAUNCHD_STATE=loaded run_installer "$PLIST_NO_SERVICE" \
     --core http://198.51.100.10:8080 --no-service --reset --enroll-code-file "$CODE_NO_SERVICE"; then
  echo "  FAIL: --no-service accepted an existing LaunchDaemon definition"
  FAIL=$((FAIL + 1))
else
  echo "  ok: --no-service refused an existing LaunchDaemon before code validation"
  PASS=$((PASS + 1))
fi
check "LaunchDaemon --no-service error explains transactional update" "omit --no-service" "${PLIST_NO_SERVICE}.log"
check "LaunchDaemon config untouched by --no-service refusal" "no-service-config" "$PLIST_NO_SERVICE"
check "LaunchDaemon token untouched by --no-service refusal" "no-service-token" "${PLIST_NO_SERVICE}.token"
check "LaunchDaemon binary untouched by --no-service refusal" "no-service-binary" "${WORK}/prefix/vedetta-sensor"
check "LaunchDaemon enrollment code untouched by --no-service refusal" "NO-SERVICE-CODE" "$CODE_NO_SERVICE"
check "LaunchDaemon stayed loaded after --no-service refusal" "loaded" "$LAUNCHD_STATE"
refute "LaunchDaemon --no-service refusal made no manager request" "bootout" "$LAUNCHD_COMMANDS"
refute "LaunchDaemon --no-service refusal never invoked the sensor" "sensor-argv=" "${PLIST_NO_SERVICE}.log"

echo "case: macOS --no-service refuses a loaded manager job after its plist was deleted"
PLIST_MANAGER_ONLY="${WORK}/no-service-manager-only.plist"
CODE_MANAGER_ONLY="${WORK}/no-service-manager-only.code"
printf 'MANAGER-ONLY-CODE' >"$CODE_MANAGER_ONLY"
chmod 0644 "$CODE_MANAGER_ONLY" # Proves the manager guard runs before secret validation.
if RUN_INSTALLER_LAUNCHD_STATE=loaded run_installer "$PLIST_MANAGER_ONLY" \
     --core http://198.51.100.10:8080 --no-service --reset --enroll-code-file "$CODE_MANAGER_ONLY"; then
  echo "  FAIL: --no-service accepted a loaded LaunchDaemon with no plist"
  FAIL=$((FAIL + 1))
else
  echo "  ok: --no-service refused a loaded LaunchDaemon with no plist"
  PASS=$((PASS + 1))
fi
check "manager-only LaunchDaemon refusal explains transactional update" "omit --no-service" "${PLIST_MANAGER_ONLY}.log"
check "manager-only LaunchDaemon enrollment code stayed untouched" "MANAGER-ONLY-CODE" "$CODE_MANAGER_ONLY"
check "manager-only LaunchDaemon stayed loaded" "loaded" "$LAUNCHD_STATE"
refute "manager-only LaunchDaemon was not stopped" "bootout" "$LAUNCHD_COMMANDS"
refute "manager-only LaunchDaemon never invoked the sensor" "sensor-argv=" "${PLIST_MANAGER_ONLY}.log"

echo "case: a custom service path cannot hide the default managed definition"
PLIST_CUSTOM_UNUSED="${WORK}/custom-unused.plist"
PLIST_DEFAULT_EXISTING="${WORK}/default-existing.plist"
write_launchd_service "$PLIST_DEFAULT_EXISTING" 'http://198.51.100.10:8080' default-service-config
CODE_DEFAULT_EXISTING="$(code_file default-existing DEFAULT-EXISTING-CODE)"
if VEDETTA_TEST_DEFAULT_SERVICE_FILE="$PLIST_DEFAULT_EXISTING" run_installer "$PLIST_CUSTOM_UNUSED" \
     --core http://198.51.100.10:8080 --no-service --reset --enroll-code-file "$CODE_DEFAULT_EXISTING"; then
  echo "  FAIL: custom path bypassed the default managed definition"
  FAIL=$((FAIL + 1))
else
  echo "  ok: custom path could not bypass the default managed definition"
  PASS=$((PASS + 1))
fi
check "default managed definition stayed intact" "default-service-config" "$PLIST_DEFAULT_EXISTING"
check "default-path refusal left enrollment code untouched" "DEFAULT-EXISTING-CODE" "$CODE_DEFAULT_EXISTING"
refute "default-path refusal made no stop request" "bootout" "$LAUNCHD_COMMANDS"

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
echo "case: Linux install WITH --enroll-code-file (systemd unit)"
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
SYSTEMD_STATE="${WORK}/systemd.state"
SYSTEMD_COMMANDS="${WORK}/systemd.commands"
: >"$SYSTEMD_COMMANDS"
printf 'inactive disabled\n' >"$SYSTEMD_STATE"
cat >"${LINUXBIN}/systemctl" <<EOF
#!/usr/bin/env bash
state="$SYSTEMD_STATE"
printf '%s\n' "\$*" >>"$SYSTEMD_COMMANDS"
read -r active enabled <"\$state"
case "\${1:-}" in
  is-active) [ "\$active" = active ] && { echo active; exit 0; }; echo inactive; exit 3 ;;
  is-enabled) echo "\$enabled"; [ "\$enabled" = enabled ] || [ "\$enabled" = enabled-runtime ] ;;
  show)
    case "\$*" in
      *'-p LoadState'*)
        if [ -n "\${VEDETTA_TEST_SYSTEMD_LOAD_STATE:-}" ]; then
          printf 'LoadState=%s\n' "\$VEDETTA_TEST_SYSTEMD_LOAD_STATE"
        elif [ "\$active" = active ] || [ -f "\${VEDETTA_SERVICE_PATH:-}" ]; then
          echo LoadState=loaded
        else
          echo LoadState=not-found
        fi
        ;;
      *'-p FragmentPath'*)
        printf 'FragmentPath=%s\n' "\${VEDETTA_TEST_SYSTEMD_FRAGMENT_PATH:-\${VEDETTA_SERVICE_PATH:-}}"
        printf 'DropInPaths=%s\n' "\${VEDETTA_TEST_SYSTEMD_DROPIN_PATHS:-}"
        ;;
      *) [ "\$active" = active ] && echo MainPID=501 || echo MainPID=0 ;;
    esac
    ;;
  stop) printf 'inactive %s\n' "\$enabled" >"\$state" ;;
  restart|start)
    case "\$enabled" in masked|masked-runtime) exit 1 ;; esac
    printf 'active %s\n' "\$enabled" >"\$state"
    ;;
  enable)
    if [ "\${2:-}" = "--runtime" ]; then
      printf '%s enabled-runtime\n' "\$active" >"\$state"
    else
      printf '%s enabled\n' "\$active" >"\$state"
    fi
    ;;
  disable) printf '%s disabled\n' "\$active" >"\$state" ;;
  mask)
    if [ "\${2:-}" = "--runtime" ]; then
      printf '%s masked-runtime\n' "\$active" >"\$state"
    else
      printf '%s masked\n' "\$active" >"\$state"
    fi
    ;;
  unmask) printf '%s disabled\n' "\$active" >"\$state" ;;
  daemon-reload) : ;;
esac
EOF
# ldconfig reports libpcap already present so ensure_libpcap_runtime short-circuits
# (this host has no apt/dnf/pacman to actually install it).
printf '#!/usr/bin/env bash\necho "\\tlibpcap.so.0.8 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libpcap.so.0.8"\n' >"${LINUXBIN}/ldconfig"
chmod +x "${LINUXBIN}"/*

UNIT4="${WORK}/vedetta-sensor.service"
CODE4="$(code_file linux ENROLL-TEST-456)"
# Linux uname mock shadows the Darwin one; reuse the shared sudo/nmap/fake binary.
PATH="${LINUXBIN}:${MOCKBIN}:${PATH}" \
VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
VEDETTA_BIN_DIR="${WORK}/prefix4" \
VEDETTA_SERVICE_PATH="$UNIT4" \
VEDETTA_SENSOR_TOKEN_FILE="${UNIT4}.token" \
VEDETTA_SENSOR_LOG="${UNIT4}.senslog" \
VEDETTA_SENSOR_LOG_FILE="${UNIT4}.daemon.log" \
VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
VEDETTA_TEST_OS=Linux \
VEDETTA_TEST_ARCH=x86_64 \
VEDETTA_SKIP_HEALTHCHECK=1 \
  bash "$INSTALL_SH" --core 'https://example.test/a%2Fb/$literal' --cidr 2001:db8::/64 --enroll-code-file "$CODE4" >"${UNIT4}.log" 2>&1

check  "unit references --core"            "--core"                      "$UNIT4"
check  "unit safely escapes systemd percent and dollar" 'https://example.test/a%%2Fb/$$literal' "$UNIT4"
check  "unit persists requested CIDR"      "2001:db8::/64"              "$UNIT4"
refute "unit omits the --enroll-code flag" "--enroll-code"               "$UNIT4"
refute "unit omits the enrollment code"    "ENROLL-TEST-456"             "$UNIT4"
check  "unit sets a service PATH"          "Environment=\"PATH="         "$UNIT4"
check  "unit has an nmap ExecStartPre gate" "ExecStartPre"               "$UNIT4"
refute "unit preflight uses no root shell"  "sh -c"                      "$UNIT4"
check  "unit pins absolute nmap"            "VEDETTA_NMAP_PATH"           "$UNIT4"
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

run_linux_installer() { # run_linux_installer <unit> <bin-dir> [install.sh args...]
  local unit="$1" bin_dir="$2"; shift 2
  PATH="${LINUXBIN}:${MOCKBIN}:${PATH}" \
  VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
  VEDETTA_BIN_DIR="$bin_dir" \
  VEDETTA_SERVICE_PATH="$unit" \
  VEDETTA_SENSOR_TOKEN_FILE="${unit}.token" \
  VEDETTA_SENSOR_LOG="${unit}.senslog" \
  VEDETTA_SENSOR_LOG_FILE="${unit}.daemon.log" \
  VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
  VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
  VEDETTA_TEST_OS=Linux \
  VEDETTA_TEST_ARCH=x86_64 \
  VEDETTA_SKIP_HEALTHCHECK=1 \
    bash "$INSTALL_SH" "$@" >"${unit}.log" 2>&1
}

echo "case: origin/main legacy unquoted systemd unit updates safely"
UNIT_LEGACY="${WORK}/legacy-vedetta-sensor.service"
cat >"$UNIT_LEGACY" <<EOF
[Unit]
Description=Vedetta Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=VEDETTA_SENSOR_TOKEN_FILE=${UNIT_LEGACY}.token
ExecStart=/usr/local/bin/vedetta-sensor --core http://198.51.100.10:8080 --cidr auto --dns --passive-discovery
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
printf 'legacy-systemd-token' >"${UNIT_LEGACY}.token"
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if run_linux_installer "$UNIT_LEGACY" "${WORK}/prefix-legacy" --core http://198.51.100.10:8080; then
  echo "  ok: verbatim origin/main legacy systemd unit accepted for same-Core update"
  PASS=$((PASS + 1))
else
  echo "  FAIL: verbatim origin/main legacy systemd unit rejected"
  FAIL=$((FAIL + 1))
fi
check "legacy systemd update rewrote modern quoted Core" ' --core "http://198.51.100.10:8080" --cidr ' "$UNIT_LEGACY"
check "legacy systemd update restored running manager state" "active enabled" "$SYSTEMD_STATE"

echo "case: legacy systemd unit with an alternate Core override is refused"
UNIT_LEGACY_OVERRIDE="${WORK}/legacy-core-override.service"
cat >"$UNIT_LEGACY_OVERRIDE" <<EOF
[Unit]
Description=Vedetta Sensor
[Service]
Environment=VEDETTA_SENSOR_TOKEN_FILE=${UNIT_LEGACY_OVERRIDE}.token
ExecStart=/usr/local/bin/vedetta-sensor --core http://198.51.100.10:8080 --cidr auto --dns --passive-discovery --core=http://203.0.113.9:8080
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
printf 'legacy-override-token' >"${UNIT_LEGACY_OVERRIDE}.token"
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if run_linux_installer "$UNIT_LEGACY_OVERRIDE" "${WORK}/prefix-legacy-override" --core http://198.51.100.10:8080; then
  echo "  FAIL: ambiguous legacy unit with --core= override was accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: ambiguous legacy unit with --core= override refused"
  PASS=$((PASS + 1))
fi
check "ambiguous legacy unit stayed running and enabled" "active enabled" "$SYSTEMD_STATE"
check "ambiguous legacy unit token stayed intact" "legacy-override-token" "${UNIT_LEGACY_OVERRIDE}.token"
refute "ambiguous legacy unit was not stopped" "stop vedetta-sensor" "$SYSTEMD_COMMANDS"

echo "case: Linux --no-service refuses an existing managed service before reading its code"
UNIT_NO_SERVICE="${WORK}/no-service-existing.service"
write_systemd_service "$UNIT_NO_SERVICE" 'http://198.51.100.10:8080' no-service-config
printf 'no-service-systemd-token' >"${UNIT_NO_SERVICE}.token"
LINUX_NO_SERVICE_BIN="${WORK}/prefix-no-service"
mkdir -p "$LINUX_NO_SERVICE_BIN"
printf '#!/usr/bin/env bash\necho no-service-systemd-binary\n' >"${LINUX_NO_SERVICE_BIN}/vedetta-sensor"
chmod +x "${LINUX_NO_SERVICE_BIN}/vedetta-sensor"
CODE_LINUX_NO_SERVICE="${WORK}/no-service-systemd.code"
printf 'NO-SERVICE-SYSTEMD-CODE' >"$CODE_LINUX_NO_SERVICE"
chmod 0644 "$CODE_LINUX_NO_SERVICE" # Would be rejected if the secret were inspected first.
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if run_linux_installer "$UNIT_NO_SERVICE" "$LINUX_NO_SERVICE_BIN" \
     --core http://198.51.100.10:8080 --no-service --reset --enroll-code-file "$CODE_LINUX_NO_SERVICE"; then
  echo "  FAIL: --no-service accepted an existing systemd definition"
  FAIL=$((FAIL + 1))
else
  echo "  ok: --no-service refused an existing systemd service before code validation"
  PASS=$((PASS + 1))
fi
check "systemd --no-service error explains transactional update" "omit --no-service" "${UNIT_NO_SERVICE}.log"
check "systemd config untouched by --no-service refusal" "no-service-config" "$UNIT_NO_SERVICE"
check "systemd token untouched by --no-service refusal" "no-service-systemd-token" "${UNIT_NO_SERVICE}.token"
check "systemd binary untouched by --no-service refusal" "no-service-systemd-binary" "${LINUX_NO_SERVICE_BIN}/vedetta-sensor"
check "systemd enrollment code untouched by --no-service refusal" "NO-SERVICE-SYSTEMD-CODE" "$CODE_LINUX_NO_SERVICE"
check "systemd stayed active/enabled after --no-service refusal" "active enabled" "$SYSTEMD_STATE"
refute "systemd --no-service refusal made no manager request" "stop vedetta-sensor" "$SYSTEMD_COMMANDS"
refute "systemd --no-service refusal never invoked the sensor" "sensor-argv=" "${UNIT_NO_SERVICE}.log"

echo "case: Linux --no-service refuses a loaded manager unit after its file was deleted"
UNIT_MANAGER_ONLY="${WORK}/no-service-manager-only.service"
LINUX_MANAGER_ONLY_BIN="${WORK}/prefix-manager-only"
mkdir -p "$LINUX_MANAGER_ONLY_BIN"
printf '#!/usr/bin/env bash\necho manager-only-binary\n' >"${LINUX_MANAGER_ONLY_BIN}/vedetta-sensor"
chmod +x "${LINUX_MANAGER_ONLY_BIN}/vedetta-sensor"
CODE_LINUX_MANAGER_ONLY="${WORK}/no-service-manager-only-systemd.code"
printf 'MANAGER-ONLY-SYSTEMD-CODE' >"$CODE_LINUX_MANAGER_ONLY"
chmod 0644 "$CODE_LINUX_MANAGER_ONLY" # Proves the manager guard runs before secret validation.
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if VEDETTA_TEST_SYSTEMD_LOAD_STATE=loaded run_linux_installer "$UNIT_MANAGER_ONLY" "$LINUX_MANAGER_ONLY_BIN" \
     --core http://198.51.100.10:8080 --no-service --reset --enroll-code-file "$CODE_LINUX_MANAGER_ONLY"; then
  echo "  FAIL: --no-service accepted a loaded systemd unit with no service file"
  FAIL=$((FAIL + 1))
else
  echo "  ok: --no-service refused a loaded systemd unit with no service file"
  PASS=$((PASS + 1))
fi
check "manager-only systemd refusal explains transactional update" "omit --no-service" "${UNIT_MANAGER_ONLY}.log"
check "manager-only systemd binary stayed intact" "manager-only-binary" "${LINUX_MANAGER_ONLY_BIN}/vedetta-sensor"
check "manager-only systemd enrollment code stayed untouched" "MANAGER-ONLY-SYSTEMD-CODE" "$CODE_LINUX_MANAGER_ONLY"
check "manager-only systemd stayed active and enabled" "active enabled" "$SYSTEMD_STATE"
refute "manager-only systemd was not stopped" "stop vedetta-sensor" "$SYSTEMD_COMMANDS"
refute "manager-only systemd never invoked the sensor" "sensor-argv=" "${UNIT_MANAGER_ONLY}.log"

echo "case: service update refuses a manager-known unit whose selected file is absent"
UNIT_VENDOR_ONLY="${WORK}/vendor-unit-selected-path.service"
CODE_VENDOR_ONLY="$(code_file vendor-only VENDOR-ONLY-CODE)"
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if VEDETTA_TEST_SYSTEMD_LOAD_STATE=loaded run_linux_installer "$UNIT_VENDOR_ONLY" "${WORK}/prefix-vendor-only" \
     --core http://198.51.100.10:8080 --enroll-code-file "$CODE_VENDOR_ONLY"; then
  echo "  FAIL: update accepted a manager-known unit with an unknown rollback file"
  FAIL=$((FAIL + 1))
else
  echo "  ok: update refused a manager-known unit with an unknown rollback file"
  PASS=$((PASS + 1))
fi
check "manager-known missing-file error names unknown registration" "already knows Vedetta" "${UNIT_VENDOR_ONLY}.log"
check "manager-known missing-file enrollment code stayed untouched" "VENDOR-ONLY-CODE" "$CODE_VENDOR_ONLY"
refute "manager-known missing-file update did not stop service" "stop vedetta-sensor" "$SYSTEMD_COMMANDS"
refute "manager-known missing-file update never invoked sensor" "sensor-argv=" "${UNIT_VENDOR_ONLY}.log"

echo "case: service update refuses a Vedetta-specific systemd drop-in"
UNIT_DROPIN="${WORK}/dropin-override.service"
DROPIN_ROOT="${WORK}/systemd-dropins"
DROPIN_DIR="${DROPIN_ROOT}/vedetta-sensor.service.d"
mkdir -p "$DROPIN_DIR"
write_systemd_service "$UNIT_DROPIN" 'http://198.51.100.10:8080' dropin-main
cat >"${DROPIN_DIR}/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/vedetta-sensor --core http://203.0.113.9:8080 --cidr auto --dns --passive-discovery
EOF
printf 'dropin-token' >"${UNIT_DROPIN}.token"
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if VEDETTA_TEST_SYSTEMD_DROPIN_ROOT="$DROPIN_ROOT" run_linux_installer "$UNIT_DROPIN" "${WORK}/prefix-dropin" \
     --core http://198.51.100.10:8080; then
  echo "  FAIL: update accepted a targeted systemd ExecStart drop-in"
  FAIL=$((FAIL + 1))
else
  echo "  ok: update refused a targeted systemd ExecStart drop-in"
  PASS=$((PASS + 1))
fi
check "targeted drop-in error explains unsupported override" "Vedetta-specific systemd drop-in" "${UNIT_DROPIN}.log"
check "targeted drop-in unit stayed intact" "dropin-main" "$UNIT_DROPIN"
check "targeted drop-in token stayed intact" "dropin-token" "${UNIT_DROPIN}.token"
refute "targeted drop-in update did not stop service" "stop vedetta-sensor" "$SYSTEMD_COMMANDS"
refute "targeted drop-in update never invoked sensor" "sensor-argv=" "${UNIT_DROPIN}.log"

echo "case: generated systemd escaping round-trips through Core guard"
: >"$SYSTEMD_COMMANDS"
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"${UNIT4}.senslog"
if run_linux_installer "$UNIT4" "${WORK}/prefix4" --core 'https://example.test/a%2Fb/$literal' --cidr 2001:db8::/64; then
  echo "  ok: generated percent/dollar escaped Core URL parsed on update"
  PASS=$((PASS + 1))
else
  echo "  FAIL: generated percent/dollar escaped Core URL was not parsed"
  FAIL=$((FAIL + 1))
fi
refute "escaped-URL update did not re-enroll" "argv=[--enroll-only" "${UNIT4}.senslog"

echo "case: systemd existing Core comparison accepts normalized equivalent"
UNIT_CORE_EQ="${WORK}/core-equivalent.service"
write_systemd_service "$UNIT_CORE_EQ" 'HTTP://CORE.Example.Test/Proxy///' core-equivalent-old
printf 'equivalent-systemd-token' >"${UNIT_CORE_EQ}.token"
printf 'inactive disabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if run_linux_installer "$UNIT_CORE_EQ" "${WORK}/prefix-core-equivalent" --core 'http://core.example.test/Proxy'; then
  echo "  ok: systemd authority case and trailing slash differences accepted"
  PASS=$((PASS + 1))
else
  echo "  FAIL: normalized-equivalent systemd Core URL rejected"
  FAIL=$((FAIL + 1))
fi
check "equivalent systemd update wrote requested Core" 'http://core.example.test/Proxy' "$UNIT_CORE_EQ"

echo "case: systemd changed Core is rejected before stop or enrollment"
UNIT_CORE_CHANGED="${WORK}/core-changed.service"
write_systemd_service "$UNIT_CORE_CHANGED" 'https://core-a.example.test/Router' core-change-blocked
printf 'unchanged-systemd-token' >"${UNIT_CORE_CHANGED}.token"
CODE_SYSTEMD_CHANGED="$(code_file systemd-core-changed RESET-SYSTEMD-CORE)"
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if run_linux_installer "$UNIT_CORE_CHANGED" "${WORK}/prefix-core-changed" --core 'https://core-b.example.test/Router' --reset --enroll-code-file "$CODE_SYSTEMD_CHANGED"; then
  echo "  FAIL: changed systemd Core URL was accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: changed systemd Core URL rejected"
  PASS=$((PASS + 1))
fi
check "systemd Core-change error explains credential migration" "credential migration" "${UNIT_CORE_CHANGED}.log"
check "rejected systemd config stayed intact" "core-change-blocked" "$UNIT_CORE_CHANGED"
check "rejected systemd token stayed intact" "unchanged-systemd-token" "${UNIT_CORE_CHANGED}.token"
check "rejected systemd service stayed running and enabled" "active enabled" "$SYSTEMD_STATE"
refute "rejected systemd update never requested stop" "stop vedetta-sensor" "$SYSTEMD_COMMANDS"
refute "rejected systemd update never enrolled" "argv=[--reset --enroll-only" "${UNIT_CORE_CHANGED}.senslog"

echo "case: generated systemd duplicate Core options are rejected"
UNIT_CORE_OVERRIDE="${WORK}/core-override.service"
write_systemd_service "$UNIT_CORE_OVERRIDE" 'http://198.51.100.10:8080' duplicate-core-blocked
sed 's# --passive-discovery$# --passive-discovery --core=http://203.0.113.9:8080#' \
  "$UNIT_CORE_OVERRIDE" >"${UNIT_CORE_OVERRIDE}.new"
mv "${UNIT_CORE_OVERRIDE}.new" "$UNIT_CORE_OVERRIDE"
printf 'unchanged-systemd-duplicate-token' >"${UNIT_CORE_OVERRIDE}.token"
CODE_SYSTEMD_OVERRIDE="$(code_file systemd-core-override RESET-SYSTEMD-DUPLICATE)"
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if run_linux_installer "$UNIT_CORE_OVERRIDE" "${WORK}/prefix-core-override" \
     --core http://198.51.100.10:8080 --reset --enroll-code-file "$CODE_SYSTEMD_OVERRIDE"; then
  echo "  FAIL: ambiguous generated systemd unit was accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: ambiguous generated systemd unit refused"
  PASS=$((PASS + 1))
fi
check "duplicate systemd config stayed intact" "duplicate-core-blocked" "$UNIT_CORE_OVERRIDE"
check "duplicate systemd token stayed intact" "unchanged-systemd-duplicate-token" "${UNIT_CORE_OVERRIDE}.token"
check "duplicate systemd service stayed running and enabled" "active enabled" "$SYSTEMD_STATE"
refute "duplicate systemd unit was not stopped" "stop vedetta-sensor" "$SYSTEMD_COMMANDS"
refute "duplicate systemd unit never enrolled" "argv=[--reset --enroll-only" "${UNIT_CORE_OVERRIDE}.senslog"

echo "case: systemd positional arguments before Core are rejected"
UNIT_POSITIONAL="${WORK}/positional-before-core.service"
cat >"$UNIT_POSITIONAL" <<EOF
[Unit]
Description=Vedetta Sensor (positional-before-core-blocked)
[Service]
ExecStart=/usr/local/bin/vedetta-sensor positional-arg --core http://198.51.100.10:8080 --cidr auto --dns --passive-discovery
EOF
printf 'unchanged-positional-token' >"${UNIT_POSITIONAL}.token"
CODE_POSITIONAL="$(code_file positional-before-core RESET-POSITIONAL-CORE)"
printf 'active enabled\n' >"$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
if run_linux_installer "$UNIT_POSITIONAL" "${WORK}/prefix-positional-before-core" \
     --core http://198.51.100.10:8080 --reset --enroll-code-file "$CODE_POSITIONAL"; then
  echo "  FAIL: systemd unit with a pre-Core positional argument was accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: systemd unit with a pre-Core positional argument refused"
  PASS=$((PASS + 1))
fi
check "positional systemd config stayed intact" "positional-before-core-blocked" "$UNIT_POSITIONAL"
check "positional systemd token stayed intact" "unchanged-positional-token" "${UNIT_POSITIONAL}.token"
check "positional systemd service stayed running and enabled" "active enabled" "$SYSTEMD_STATE"
refute "positional systemd unit was not stopped" "stop vedetta-sensor" "$SYSTEMD_COMMANDS"
refute "positional systemd unit never enrolled" "argv=[--reset --enroll-only" "${UNIT_POSITIONAL}.senslog"

# Source selection must never drift between a selected release asset and an ABI
# rebuild, while VEDETTA_REF mirrors --ref and forces that exact published source.
echo "case: exact source-ref selection"
REFBIN="${WORK}/refbin"
mkdir -p "$REFBIN"
printf '#!/usr/bin/env bash\nexit 0\n' >"${REFBIN}/curl"
chmod +x "${REFBIN}/curl"
REF_OUT="${WORK}/ref.out"
PATH="${REFBIN}:${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 VEDETTA_TEST_SELECT_SOURCE_REF=1 \
VEDETTA_TEST_RESOLVED_RELEASE_TAG=v0.1.0-asset VEDETTA_REF=v0.1.0-ref \
  bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"$REF_OUT"
check "VEDETTA_REF wins and forces source" "ref=v0.1.0-ref force_source=1" "$REF_OUT"
PATH="${REFBIN}:${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 VEDETTA_TEST_SELECT_SOURCE_REF=1 \
VEDETTA_TEST_RESOLVED_RELEASE_TAG=v0.1.0-asset \
  bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"$REF_OUT"
check "ABI fallback retains selected asset tag" "ref=v0.1.0-asset force_source=0" "$REF_OUT"

echo "case: packaged Go symlinks are skipped without aborting source fallback"
GO_CANDIDATE_DIR="${WORK}/go-candidate"
mkdir -p "$GO_CANDIDATE_DIR"
printf '#!/usr/bin/env bash\nexit 0\n' >"${GO_CANDIDATE_DIR}/go-real"
chmod +x "${GO_CANDIDATE_DIR}/go-real"
ln -s "${GO_CANDIDATE_DIR}/go-real" "${GO_CANDIDATE_DIR}/go-link"
if PATH="${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
   VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 \
   VEDETTA_TEST_GO_CANDIDATE="${GO_CANDIDATE_DIR}/go-real" \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 >/dev/null 2>&1; then
  echo "  ok: physical Go candidate accepted"
  PASS=$((PASS + 1))
else
  echo "  FAIL: physical Go candidate rejected"
  FAIL=$((FAIL + 1))
fi
if PATH="${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
   VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 \
   VEDETTA_TEST_GO_CANDIDATE="${GO_CANDIDATE_DIR}/go-link" \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 >/dev/null 2>&1; then
  echo "  FAIL: symlinked Go candidate accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: symlinked Go candidate skipped"
  PASS=$((PASS + 1))
fi

echo "case: downloaded Go version parsing is strict"
for valid_go in go1.25.0 go2.0.1; do
  if PATH="${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
     VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 VEDETTA_TEST_GO_VERSION="$valid_go" \
       bash "$INSTALL_SH" --core http://198.51.100.10:8080 >/dev/null 2>&1; then
    echo "  ok: accepted strict version $valid_go"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: rejected strict version $valid_go"
    FAIL=$((FAIL + 1))
  fi
done
for invalid_go in go1.25 go1.25.0.1 go1.25.0rc1 go1.25/0 1.25.0; do
  if PATH="${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
     VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 VEDETTA_TEST_GO_VERSION="$invalid_go" \
       bash "$INSTALL_SH" --core http://198.51.100.10:8080 >/dev/null 2>&1; then
    echo "  FAIL: accepted malformed version $invalid_go"
    FAIL=$((FAIL + 1))
  else
    echo "  ok: rejected malformed version $invalid_go"
    PASS=$((PASS + 1))
  fi
done

echo "case: symlinked install ancestry is rejected before creation"
STATBIN="${WORK}/statbin"
mkdir -p "$STATBIN" "${WORK_PHYSICAL}/physical-parent"
ln -s "${WORK_PHYSICAL}/physical-parent" "${WORK_PHYSICAL}/symlink-parent"
cat >"${STATBIN}/stat" <<'EOF'
#!/usr/bin/env bash
printf '0 755\n'
EOF
chmod +x "${STATBIN}/stat"
SYMLINK_LOG="${WORK}/symlink.log"
if PATH="${STATBIN}:${MOCKBIN}:${PATH}" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
   VEDETTA_TEST_ENFORCE_PATH_VALIDATION=1 VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 \
   VEDETTA_BIN_DIR="${WORK_PHYSICAL}/symlink-parent/bin" \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 --no-service >"$SYMLINK_LOG" 2>&1; then
  echo "  FAIL: symlinked install ancestry accepted"
  FAIL=$((FAIL + 1))
else
  echo "  ok: symlinked install ancestry rejected"
  PASS=$((PASS + 1))
fi
check "symlink rejection identifies the component" "symlink component" "$SYMLINK_LOG"
check "staging uses exclusive unpredictable directories" 'mktemp -d "${BIN_DIR}/.vedetta-install.XXXXXXXX"' "$INSTALL_SH"
check "privileged tools use sanitized root runner" "SUDO=root_run" "$INSTALL_SH"

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
while [ \$# -gt 0 ]; do
  case "\$1" in
    -u) shift 2 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
[ \$# -gt 0 ] || exit 0
exec "\$@"
EOF

# brew: record args; \`list\` reports "not installed" so \`install\` runs.
cat >"${BREWROOT}/bin/brew" <<EOF
#!/usr/bin/env bash
echo "\$@" >>"${BREW_LOG}"
[ "\${1:-}" = "list" ] && exit 1
exit 0
EOF

# launchctl reports no registered job (no nmap mock here => ensure_nmap must reach brew).
cat >"${BREWROOT}/bin/launchctl" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = print ] && exit 113
exit 0
EOF
chmod +x "${BREWROOT}/bin/"*

PLIST3="${WORK}/brew-root.plist"
# Constrained PATH: BREWROOT mocks + core utils only. Deliberately EXCLUDES
# ${MOCKBIN} (its nmap stub would short-circuit ensure_nmap) and the host's real
# nmap, so ensure_nmap must install it via brew. The fake sensor binary is passed
# by absolute path via VEDETTA_SENSOR_BINARY, so it needs no PATH entry.
# VEDETTA_DAEMON_PATH pins the daemon PATH to a set with NO nmap so ensure_nmap's
# resolve-check misses (the default daemon PATH hardcodes /opt/homebrew/bin, where the
# CI/dev host may already have a real nmap that would wrongly short-circuit the install).
PATH="${BREWROOT}/bin:/usr/bin:/bin" \
VEDETTA_DAEMON_PATH="${BREWROOT}/bin:/usr/bin:/bin" \
VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
VEDETTA_TEST_OS=Darwin \
VEDETTA_TEST_ARCH=arm64 \
VEDETTA_TEST_UID=0 \
VEDETTA_TEST_BREW_UID=501 \
SUDO_USER="operator" \
VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
VEDETTA_BIN_DIR="${WORK}/prefix3" \
VEDETTA_PLIST_PATH="$PLIST3" \
  bash "$INSTALL_SH" --core http://198.51.100.10:8080 --no-service >"${PLIST3}.log" 2>&1 || true

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

# --- Focused health-gate tests. These call only health_check through an explicit
#     test-only entrypoint; no install, download, enrollment, or service mutation. ---
run_health_case() { # run_health_case <name> <Darwin|Linux> <mode> <success|failure>
  local name="$1" os="$2" mode="$3" expected="$4"
  local hroot="${WORK}/health-${name}" hbin state seq log
  hbin="${hroot}/bin"; state="${hroot}/state"; seq="${hroot}/pids"; log="${hroot}/sensor.log"
  mkdir -p "$hbin"
  printf '0' >"$state"
  case "$mode" in
    stable)     printf '401\n401\n401\n' >"$seq"; printf 'Device scanner ready\n' >"$log" ;;
    large-stable)
      printf '401\n401\n401\n' >"$seq"
      printf 'Device scanner ready\n' >"$log"
      dd if=/dev/zero bs=1048576 count=8 2>/dev/null | tr '\000' x >>"$log"
      ;;
    pid-change) printf '401\n402\n402\n' >"$seq"; printf 'Device scanner ready\n' >"$log" ;;
    stopped)    : >"$seq"; : >"$log" ;;
    fatal)      printf '401\n' >"$seq"; printf 'Device scanner ready\ndevice scanner unavailable\n' >"$log" ;;
    large-fatal)
      printf '401\n401\n401\n' >"$seq"
      printf 'device scanner unavailable\n' >"$log"
      dd if=/dev/zero bs=1048576 count=8 2>/dev/null | tr '\000' x >>"$log"
      printf '\nDevice scanner ready\n' >>"$log"
      ;;
  esac
  cat >"${hbin}/uname" <<EOF
#!/usr/bin/env bash
[ "\${1:-}" = "-m" ] && { echo arm64; exit 0; }
echo ${os}
EOF
  cat >"${hbin}/sudo" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do case "$1" in -*) shift ;; *) break ;; esac; done
[ "$#" -gt 0 ] || exit 0
exec "$@"
EOF
  cat >"${hbin}/launchctl" <<EOF
#!/usr/bin/env bash
[ "$mode" = "stopped" ] && exit 1
i=\$(cat "$state"); i=\$((i + 1)); printf '%s' "\$i" >"$state"
pid=\$(sed -n "\${i}p" "$seq")
[ -n "\$pid" ] || exit 1
printf 'state = running\n    pid = %s\n' "\$pid"
EOF
  cat >"${hbin}/systemctl" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in
  is-active)
    [ "$mode" = "stopped" ] && { echo inactive; exit 3; }
    echo active
    ;;
  show)
    i=\$(cat "$state"); i=\$((i + 1)); printf '%s' "\$i" >"$state"
    pid=\$(sed -n "\${i}p" "$seq")
    printf 'MainPID=%s\n' "\${pid:-0}"
    ;;
esac
EOF
  chmod +x "${hbin}/"*

  if PATH="${hbin}:/usr/bin:/bin:/usr/sbin:/sbin" \
     VEDETTA_TEST_HEALTH_ONLY=1 \
     VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
     VEDETTA_TEST_OS="$os" \
     VEDETTA_TEST_ARCH=arm64 \
     VEDETTA_SENSOR_LOG_FILE="$log" \
     VEDETTA_HEALTH_MAX_POLLS=3 \
     VEDETTA_HEALTH_STABLE_POLLS=2 \
     VEDETTA_HEALTH_POLL_SECONDS=0 \
       bash "$INSTALL_SH" --core http://198.51.100.10:8080 >/dev/null 2>&1; then
    actual=success
  else
    actual=failure
  fi
  if [ "$actual" = "$expected" ]; then
    echo "  ok: health $name -> $expected"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: health $name expected $expected, got $actual"
    FAIL=$((FAIL + 1))
  fi
}

echo "case: deterministic service health gates"
run_health_case mac-stable Darwin stable success
run_health_case mac-pid-change Darwin pid-change failure
run_health_case mac-fatal Darwin fatal failure
run_health_case mac-large-stable Darwin large-stable success
run_health_case mac-large-fatal Darwin large-fatal failure
run_health_case linux-stable Linux stable success
run_health_case linux-stopped Linux stopped failure
run_health_case linux-restart Linux pid-change failure

echo "case: failed no-service enrollment restores only the prior binary"
NOSVCROOT="${WORK}/no-service-rollback"
NOSVCBIN="${NOSVCROOT}/prefix"
NOSVCPLIST="${NOSVCROOT}/unused.plist"
mkdir -p "$NOSVCBIN"
printf '#!/usr/bin/env bash\necho old-no-service-binary\n' >"${NOSVCBIN}/vedetta-sensor"
chmod +x "${NOSVCBIN}/vedetta-sensor"
cat >"${NOSVCROOT}/failing-sensor" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  --version) echo failing-enrollment-fixture; exit 0 ;;
  --check) exit 0 ;;
  --enroll-only) exit 1 ;;
esac
exit 0
EOF
chmod +x "${NOSVCROOT}/failing-sensor"
NOSVCCODE="$(code_file no-service-rollback FAILING-NO-SERVICE-CODE)"
printf 'absent\n' >"$LAUNCHD_STATE"
if PATH="${MOCKBIN}:${PATH}" \
   VEDETTA_SENSOR_BINARY="${NOSVCROOT}/failing-sensor" \
   VEDETTA_BIN_DIR="$NOSVCBIN" \
   VEDETTA_PLIST_PATH="$NOSVCPLIST" \
   VEDETTA_SENSOR_TOKEN_FILE="${NOSVCROOT}/sensor-token" \
   VEDETTA_SENSOR_LOG_FILE="${NOSVCROOT}/sensor.log" \
   VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
   VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
   VEDETTA_TEST_OS=Darwin \
   VEDETTA_TEST_ARCH=arm64 \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 --no-service \
       --enroll-code-file "$NOSVCCODE" >"${NOSVCROOT}/install.log" 2>&1; then
  echo "  FAIL: failing no-service enrollment unexpectedly succeeded"
  FAIL=$((FAIL + 1))
else
  echo "  ok: failing no-service enrollment failed"
  PASS=$((PASS + 1))
fi
check "no-service rollback restored the prior binary" "old-no-service-binary" "${NOSVCBIN}/vedetta-sensor"
refute "no-service rollback did not claim an incomplete config restore" "rollback was incomplete" "${NOSVCROOT}/install.log"

# --- Failed service health restores both the prior binary and prior config. ---
echo "case: failed update rolls back"
RBROOT="${WORK}/rollback"
RBBIN="${RBROOT}/prefix"
RBPLIST="${RBROOT}/com.vedetta.sensor.plist"
mkdir -p "$RBBIN"
printf '#!/usr/bin/env bash\necho old-binary\n' >"${RBBIN}/vedetta-sensor"
chmod +x "${RBBIN}/vedetta-sensor"
write_launchd_service "$RBPLIST" 'http://198.51.100.10:8080' old-config
RB_BIN_INODE="$(inode_of "${RBBIN}/vedetta-sensor")"
RB_CONFIG_INODE="$(inode_of "$RBPLIST")"
printf 'existing-token' >"${RBPLIST}.token"
printf 'prior-log-marker\nDevice scanner ready\n' >"${RBPLIST}.daemon.log"
printf 'loaded\n' >"$LAUNCHD_STATE"
if PATH="${MOCKBIN}:${PATH}" \
   VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
   VEDETTA_BIN_DIR="$RBBIN" \
   VEDETTA_PLIST_PATH="$RBPLIST" \
   VEDETTA_SENSOR_TOKEN_FILE="${RBPLIST}.token" \
   VEDETTA_SENSOR_LOG_FILE="${RBPLIST}.daemon.log" \
   VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
   VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
   VEDETTA_TEST_OS=Darwin \
   VEDETTA_TEST_ARCH=arm64 \
   VEDETTA_HEALTH_MAX_POLLS=1 \
   VEDETTA_HEALTH_STABLE_POLLS=1 \
   VEDETTA_HEALTH_POLL_SECONDS=0 \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${RBPLIST}.log" 2>&1; then
  echo "  FAIL: unhealthy replacement unexpectedly succeeded"
  FAIL=$((FAIL + 1))
else
  echo "  ok: unhealthy replacement failed"
  PASS=$((PASS + 1))
fi
check "prior binary restored" "old-binary" "${RBBIN}/vedetta-sensor"
check "prior config restored" "old-config" "$RBPLIST"
check "prior macOS sensor log retained on rollback" "prior-log-marker" "${RBPLIST}.daemon.log"
check "prior LaunchDaemon loaded state restored" "loaded" "$LAUNCHD_STATE"
if [ "$(inode_of "${RBBIN}/vedetta-sensor")" = "$RB_BIN_INODE" ] \
   && [ "$(inode_of "$RBPLIST")" = "$RB_CONFIG_INODE" ]; then
  echo "  ok: rollback restored original binary and plist inodes"
  PASS=$((PASS + 1))
else
  echo "  FAIL: rollback did not restore original binary and plist inodes"
  FAIL=$((FAIL + 1))
fi

echo "case: rollback restores a loaded but disabled LaunchDaemon"
RBDROOT="${WORK}/rollback-disabled-launchd"
RBDBIN="${RBDROOT}/prefix"
RBDPLIST="${RBDROOT}/com.vedetta.sensor.plist"
mkdir -p "$RBDBIN"
printf '#!/usr/bin/env bash\necho old-disabled-binary\n' >"${RBDBIN}/vedetta-sensor"
chmod +x "${RBDBIN}/vedetta-sensor"
write_launchd_service "$RBDPLIST" 'http://198.51.100.10:8080' old-disabled-config
printf 'existing-token' >"${RBDPLIST}.token"
printf 'loaded\n' >"$LAUNCHD_STATE"
printf 'true\n' >"$LAUNCHD_DISABLED_STATE_FILE"
: >"$LAUNCHD_COMMANDS"
if PATH="${MOCKBIN}:${PATH}" \
   VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
   VEDETTA_BIN_DIR="$RBDBIN" \
   VEDETTA_PLIST_PATH="$RBDPLIST" \
   VEDETTA_SENSOR_TOKEN_FILE="${RBDPLIST}.token" \
   VEDETTA_SENSOR_LOG_FILE="${RBDPLIST}.daemon.log" \
   VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
   VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
   VEDETTA_TEST_OS=Darwin \
   VEDETTA_TEST_ARCH=arm64 \
   VEDETTA_HEALTH_MAX_POLLS=1 \
   VEDETTA_HEALTH_STABLE_POLLS=2 \
   VEDETTA_HEALTH_POLL_SECONDS=0 \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${RBDPLIST}.log" 2>&1; then
  echo "  FAIL: unhealthy disabled LaunchDaemon replacement unexpectedly succeeded"
  FAIL=$((FAIL + 1))
else
  echo "  ok: unhealthy disabled LaunchDaemon replacement failed"
  PASS=$((PASS + 1))
fi
check "disabled LaunchDaemon prior binary restored" "old-disabled-binary" "${RBDBIN}/vedetta-sensor"
check "disabled LaunchDaemon prior config restored" "old-disabled-config" "$RBDPLIST"
check "disabled LaunchDaemon loaded state restored" "loaded" "$LAUNCHD_STATE"
check "disabled LaunchDaemon disabled state restored" "true" "$LAUNCHD_DISABLED_STATE_FILE"
RBD_ENABLE_LINE="$(grep -n '^enable system/com.vedetta.sensor$' "$LAUNCHD_COMMANDS" | tail -1 | cut -d: -f1)"
RBD_LOAD_LINE="$(grep -n '^load ' "$LAUNCHD_COMMANDS" | tail -1 | cut -d: -f1)"
RBD_DISABLE_LINE="$(grep -n '^disable system/com.vedetta.sensor$' "$LAUNCHD_COMMANDS" | tail -1 | cut -d: -f1)"
if [ -n "$RBD_ENABLE_LINE" ] && [ -n "$RBD_LOAD_LINE" ] && [ -n "$RBD_DISABLE_LINE" ] \
   && [ "$RBD_ENABLE_LINE" -lt "$RBD_LOAD_LINE" ] && [ "$RBD_LOAD_LINE" -lt "$RBD_DISABLE_LINE" ]; then
  echo "  ok: rollback enabled before load and disabled only after restoring load state"
  PASS=$((PASS + 1))
else
  echo "  FAIL: disabled LaunchDaemon rollback manager operations were out of order"
  FAIL=$((FAIL + 1))
fi
printf 'false\n' >"$LAUNCHD_DISABLED_STATE_FILE"

echo "case: inaccessible rollback backups are preserved for recovery"
FAILBACKROOT="${WORK}/rollback-backup-failure"
FAILBACKBIN="${FAILBACKROOT}/prefix"
FAILBACKPLIST="${FAILBACKROOT}/com.vedetta.sensor.plist"
FAILBACKMOCK="${FAILBACKROOT}/bin"
mkdir -p "$FAILBACKBIN" "$FAILBACKMOCK"
printf '#!/usr/bin/env bash\necho recoverable-old-binary\n' >"${FAILBACKBIN}/vedetta-sensor"
chmod +x "${FAILBACKBIN}/vedetta-sensor"
write_launchd_service "$FAILBACKPLIST" 'http://198.51.100.10:8080' recoverable-old-config
printf 'existing-token' >"${FAILBACKPLIST}.token"
cat >"${FAILBACKMOCK}/sudo" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do
  case "$1" in
    -u) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
[ "$#" -gt 0 ] || exit 0
is_backup=0
for arg in "$@"; do
  case "$arg" in */previous) is_backup=1 ;; esac
done
if [ "$is_backup" = 1 ] && [[ " $* " == *" test -f "* ]]; then
  exit 1
fi
exec "$@"
EOF
chmod +x "${FAILBACKMOCK}/sudo"
printf 'loaded\n' >"$LAUNCHD_STATE"
if PATH="${FAILBACKMOCK}:${MOCKBIN}:${PATH}" \
   VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
   VEDETTA_BIN_DIR="$FAILBACKBIN" \
   VEDETTA_PLIST_PATH="$FAILBACKPLIST" \
   VEDETTA_SENSOR_TOKEN_FILE="${FAILBACKPLIST}.token" \
   VEDETTA_SENSOR_LOG_FILE="${FAILBACKPLIST}.daemon.log" \
   VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
   VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
   VEDETTA_TEST_UID=1000 \
   VEDETTA_TEST_OS=Darwin \
   VEDETTA_TEST_ARCH=arm64 \
   VEDETTA_HEALTH_MAX_POLLS=1 \
   VEDETTA_HEALTH_STABLE_POLLS=2 \
   VEDETTA_HEALTH_POLL_SECONDS=0 \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${FAILBACKPLIST}.log" 2>&1; then
  echo "  FAIL: installation with inaccessible backups unexpectedly succeeded"
  FAIL=$((FAIL + 1))
else
  echo "  ok: inaccessible backups made rollback fail closed"
  PASS=$((PASS + 1))
fi
check "backup failure is explicit" "backup is missing or inaccessible" "${FAILBACKPLIST}.log"
if [ -f "${FAILBACKBIN}/vedetta-sensor" ] && [ -f "$FAILBACKPLIST" ]; then
  echo "  ok: rollback did not delete installed candidates when prior backups were inaccessible"
  PASS=$((PASS + 1))
else
  echo "  FAIL: rollback deleted installed candidates when prior backups were inaccessible"
  FAIL=$((FAIL + 1))
fi
check "mixed rollback state was left stopped" "absent" "$LAUNCHD_STATE"
check "mixed rollback refused a manager restart" "refusing to load or start" "${FAILBACKPLIST}.log"
if find "$FAILBACKROOT" -type f -path '*/.vedetta-*/previous' | grep -q .; then
  echo "  ok: inaccessible prior files remained in preserved transaction directories"
  PASS=$((PASS + 1))
else
  echo "  FAIL: prior files were not preserved for manual recovery"
  FAIL=$((FAIL + 1))
fi

echo "case: unverified service stop blocks replacement"
STOPROOT="${WORK}/stop-refusal"
STOPBIN="${STOPROOT}/prefix"
STOPPLIST="${STOPROOT}/com.vedetta.sensor.plist"
mkdir -p "$STOPBIN"
printf '#!/usr/bin/env bash\necho never-replaced\n' >"${STOPBIN}/vedetta-sensor"
chmod +x "${STOPBIN}/vedetta-sensor"
write_launchd_service "$STOPPLIST" 'http://198.51.100.10:8080' never-replaced-config
printf 'existing-token' >"${STOPPLIST}.token"
printf 'sticky\n' >"$LAUNCHD_STATE"
if PATH="${MOCKBIN}:${PATH}" VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" \
   VEDETTA_BIN_DIR="$STOPBIN" VEDETTA_PLIST_PATH="$STOPPLIST" \
   VEDETTA_SENSOR_TOKEN_FILE="${STOPPLIST}.token" VEDETTA_SENSOR_LOG_FILE="${STOPPLIST}.daemon.log" \
   VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 \
   VEDETTA_TEST_OS=Darwin VEDETTA_TEST_ARCH=arm64 VEDETTA_SKIP_HEALTHCHECK=1 \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${STOPPLIST}.log" 2>&1; then
  echo "  FAIL: replacement continued after manager refused stop"
  FAIL=$((FAIL + 1))
else
  echo "  ok: replacement aborted after manager refused stop"
  PASS=$((PASS + 1))
fi
check "stop refusal is explicit" "refusing to replace files" "${STOPPLIST}.log"
check "binary stayed intact after stop refusal" "never-replaced" "${STOPBIN}/vedetta-sensor"
check "config stayed intact after stop refusal" "never-replaced-config" "$STOPPLIST"

echo "case: failed Linux update restores enabled and running manager state"
LBR="${WORK}/linux-rollback"
LBBIN="${LBR}/prefix"
LBUNIT="${LBR}/vedetta-sensor.service"
mkdir -p "$LBBIN"
printf '#!/usr/bin/env bash\necho old-linux-binary\n' >"${LBBIN}/vedetta-sensor"
chmod +x "${LBBIN}/vedetta-sensor"
write_systemd_service "$LBUNIT" 'http://198.51.100.10:8080' old-linux-config
LB_BIN_INODE="$(inode_of "${LBBIN}/vedetta-sensor")"
LB_CONFIG_INODE="$(inode_of "$LBUNIT")"
printf 'existing-token' >"${LBUNIT}.token"
printf 'active enabled\n' >"$SYSTEMD_STATE"
if PATH="${LINUXBIN}:${MOCKBIN}:${PATH}" \
   VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" VEDETTA_BIN_DIR="$LBBIN" \
   VEDETTA_SERVICE_PATH="$LBUNIT" VEDETTA_SENSOR_TOKEN_FILE="${LBUNIT}.token" \
   VEDETTA_SENSOR_LOG_FILE="${LBUNIT}.daemon.log" VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
   VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 VEDETTA_TEST_OS=Linux VEDETTA_TEST_ARCH=x86_64 \
   VEDETTA_HEALTH_MAX_POLLS=1 VEDETTA_HEALTH_STABLE_POLLS=2 VEDETTA_HEALTH_POLL_SECONDS=0 \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${LBUNIT}.log" 2>&1; then
  echo "  FAIL: unhealthy Linux replacement unexpectedly succeeded"
  FAIL=$((FAIL + 1))
else
  echo "  ok: unhealthy Linux replacement failed"
  PASS=$((PASS + 1))
fi
check "Linux prior binary restored" "old-linux-binary" "${LBBIN}/vedetta-sensor"
check "Linux prior config restored" "old-linux-config" "$LBUNIT"
check "Linux enabled/running state restored" "active enabled" "$SYSTEMD_STATE"
: >"$SYSTEMD_COMMANDS"
printf 'active enabled-runtime\n' >"$SYSTEMD_STATE"
if PATH="${LINUXBIN}:${MOCKBIN}:${PATH}" \
   VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" VEDETTA_BIN_DIR="$LBBIN" \
   VEDETTA_SERVICE_PATH="$LBUNIT" VEDETTA_SENSOR_TOKEN_FILE="${LBUNIT}.token" \
   VEDETTA_SENSOR_LOG_FILE="${LBUNIT}.daemon.log" VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
   VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 VEDETTA_TEST_OS=Linux VEDETTA_TEST_ARCH=x86_64 \
   VEDETTA_HEALTH_MAX_POLLS=1 VEDETTA_HEALTH_STABLE_POLLS=2 VEDETTA_HEALTH_POLL_SECONDS=0 \
     bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${LBUNIT}.runtime.log" 2>&1; then
  echo "  FAIL: unhealthy runtime-enabled Linux replacement unexpectedly succeeded"
  FAIL=$((FAIL + 1))
else
  echo "  ok: unhealthy runtime-enabled Linux replacement failed"
  PASS=$((PASS + 1))
fi
check "Linux runtime-enabled state restored exactly" "active enabled-runtime" "$SYSTEMD_STATE"
DISABLE_LINE="$(grep -n '^disable vedetta-sensor$' "$SYSTEMD_COMMANDS" | tail -1 | cut -d: -f1)"
RUNTIME_LINE="$(grep -n '^enable --runtime vedetta-sensor$' "$SYSTEMD_COMMANDS" | tail -1 | cut -d: -f1)"
if [ -n "$DISABLE_LINE" ] && [ -n "$RUNTIME_LINE" ] && [ "$DISABLE_LINE" -lt "$RUNTIME_LINE" ]; then
  echo "  ok: runtime rollback removes persistent enablement before restoring runtime enablement"
  PASS=$((PASS + 1))
else
  echo "  FAIL: runtime rollback did not disable persistent enablement before --runtime enable"
  FAIL=$((FAIL + 1))
fi
for masked_state in masked masked-runtime; do
  : >"$SYSTEMD_COMMANDS"
  printf 'inactive %s\n' "$masked_state" >"$SYSTEMD_STATE"
  if PATH="${LINUXBIN}:${MOCKBIN}:${PATH}" \
     VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" VEDETTA_BIN_DIR="$LBBIN" \
     VEDETTA_SERVICE_PATH="$LBUNIT" VEDETTA_SENSOR_TOKEN_FILE="${LBUNIT}.token" \
     VEDETTA_SENSOR_LOG_FILE="${LBUNIT}.daemon.log" VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
     VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 VEDETTA_TEST_OS=Linux VEDETTA_TEST_ARCH=x86_64 \
     VEDETTA_HEALTH_MAX_POLLS=1 VEDETTA_HEALTH_STABLE_POLLS=2 VEDETTA_HEALTH_POLL_SECONDS=0 \
       bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${LBUNIT}.${masked_state}.log" 2>&1; then
    echo "  FAIL: unhealthy $masked_state Linux replacement unexpectedly succeeded"
    FAIL=$((FAIL + 1))
  else
    echo "  ok: unhealthy $masked_state Linux replacement failed"
    PASS=$((PASS + 1))
  fi
  check "Linux $masked_state state restored exactly" "inactive $masked_state" "$SYSTEMD_STATE"
  if [ "$masked_state" = "masked-runtime" ]; then
    check "runtime mask rollback issued scoped mask" "mask --runtime vedetta-sensor" "$SYSTEMD_COMMANDS"
  else
    check "persistent mask rollback issued persistent mask" "mask vedetta-sensor" "$SYSTEMD_COMMANDS"
  fi
done
for masked_state in masked masked-runtime; do
  : >"$SYSTEMD_COMMANDS"
  printf 'active %s\n' "$masked_state" >"$SYSTEMD_STATE"
  if PATH="${LINUXBIN}:${MOCKBIN}:${PATH}" \
     VEDETTA_SENSOR_BINARY="${MOCKBIN}/fake-vedetta-sensor" VEDETTA_BIN_DIR="$LBBIN" \
     VEDETTA_SERVICE_PATH="$LBUNIT" VEDETTA_SENSOR_TOKEN_FILE="${LBUNIT}.token" \
     VEDETTA_SENSOR_LOG_FILE="${LBUNIT}.daemon.log" VEDETTA_NMAP_PATH="${MOCKBIN}/nmap" \
     VEDETTA_ALLOW_UNSAFE_TEST_PATHS=1 VEDETTA_TEST_OS=Linux VEDETTA_TEST_ARCH=x86_64 \
     VEDETTA_HEALTH_MAX_POLLS=1 VEDETTA_HEALTH_STABLE_POLLS=2 VEDETTA_HEALTH_POLL_SECONDS=0 \
       bash "$INSTALL_SH" --core http://198.51.100.10:8080 >"${LBUNIT}.running-${masked_state}.log" 2>&1; then
    echo "  FAIL: unhealthy running $masked_state Linux replacement unexpectedly succeeded"
    FAIL=$((FAIL + 1))
  else
    echo "  ok: unhealthy running $masked_state Linux replacement failed"
    PASS=$((PASS + 1))
  fi
  check "Linux running $masked_state state restored exactly" "active $masked_state" "$SYSTEMD_STATE"
  if [ "$masked_state" = masked-runtime ]; then
    RUNTIME_UNMASK_LINE="$(grep -n '^unmask --runtime vedetta-sensor$' "$SYSTEMD_COMMANDS" | tail -1 | cut -d: -f1)"
    RUNTIME_MASK_LINE="$(grep -n '^mask --runtime vedetta-sensor$' "$SYSTEMD_COMMANDS" | tail -1 | cut -d: -f1)"
  else
    RUNTIME_UNMASK_LINE="$(grep -n '^unmask vedetta-sensor$' "$SYSTEMD_COMMANDS" | tail -1 | cut -d: -f1)"
    RUNTIME_MASK_LINE="$(grep -n '^mask vedetta-sensor$' "$SYSTEMD_COMMANDS" | tail -1 | cut -d: -f1)"
  fi
  RUNTIME_RESTART_LINE="$(grep -n '^restart vedetta-sensor$' "$SYSTEMD_COMMANDS" | tail -1 | cut -d: -f1)"
  if [ -n "$RUNTIME_UNMASK_LINE" ] && [ -n "$RUNTIME_RESTART_LINE" ] && [ -n "$RUNTIME_MASK_LINE" ] \
     && [ "$RUNTIME_UNMASK_LINE" -lt "$RUNTIME_RESTART_LINE" ] \
     && [ "$RUNTIME_RESTART_LINE" -lt "$RUNTIME_MASK_LINE" ]; then
    echo "  ok: running $masked_state rollback unmasked, restarted, then restored its mask"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: running $masked_state rollback manager operations were out of order"
    FAIL=$((FAIL + 1))
  fi
done
printf 'inactive masked\n' >"$SYSTEMD_STATE"
"${LINUXBIN}/systemctl" unmask vedetta-sensor >/dev/null
check "systemd mock unmask removes the mask" "inactive disabled" "$SYSTEMD_STATE"
if [ "$(inode_of "${LBBIN}/vedetta-sensor")" = "$LB_BIN_INODE" ] \
   && [ "$(inode_of "$LBUNIT")" = "$LB_CONFIG_INODE" ]; then
  echo "  ok: Linux rollback preserved original binary and unit inodes"
  PASS=$((PASS + 1))
else
  echo "  FAIL: Linux rollback did not preserve original binary and unit inodes"
  FAIL=$((FAIL + 1))
fi
check "prebuilt selection persists its exact tag" 'RESOLVED_RELEASE_TAG="$selected_tag"' "$INSTALL_SH"

echo ""
echo "installer test: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
