#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=scripts/lib/port-config.sh
source "${REPO_ROOT}/scripts/lib/port-config.sh"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vedetta-port-test.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

pass_count=0
fail() {
  echo "not ok - $*" >&2
  exit 1
}
assert_eq() {
  local expected="$1" actual="$2" label="$3"
  [ "${expected}" = "${actual}" ] || fail "${label}: expected '${expected}', got '${actual}'"
  pass_count=$((pass_count + 1))
  echo "ok ${pass_count} - ${label}"
}
assert_true() {
  local label="$1"
  shift
  "$@" || fail "${label}"
  pass_count=$((pass_count + 1))
  echo "ok ${pass_count} - ${label}"
}
assert_false() {
  local label="$1"
  shift
  if "$@"; then
    fail "${label}"
  fi
  pass_count=$((pass_count + 1))
  echo "ok ${pass_count} - ${label}"
}
skip() {
  pass_count=$((pass_count + 1))
  echo "ok ${pass_count} - $* # SKIP"
}

DOTENV="${TMP_DIR}/compose.env"
printf '%s\n' \
  '# ignored' \
  ' VEDETTA_BACKEND_PORT = "18080" # operator override' \
  "VEDETTA_FRONTEND_PORT='13107'   # quoted" \
  'VEDETTA_COLLECTOR_PORT=15140 # unquoted' \
  'export VEDETTA_EXPORTED_PORT=18090' \
  'BASE_PORT=18091' \
  'VEDETTA_REFERENCED_PORT=${BASE_PORT}' \
  'VEDETTA_DOUBLE_REF="${BASE_PORT}"' \
  "VEDETTA_SINGLE_REF='\${BASE_PORT}'" \
  'CYCLE_A=${CYCLE_B}' \
  'CYCLE_B=${CYCLE_A}' \
  'VEDETTA_DUPLICATE_PORT=1111' \
  'VEDETTA_DUPLICATE_PORT = 2222' >"${DOTENV}"

assert_eq 18080 "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${DOTENV}")" "double-quoted dotenv port"
assert_eq 13107 "$(vedetta_resolve_port VEDETTA_FRONTEND_PORT 3107 "${DOTENV}")" "single-quoted dotenv port"
assert_eq 15140 "$(vedetta_resolve_port VEDETTA_COLLECTOR_PORT 5140 "${DOTENV}")" "unquoted port with comment"
assert_eq 18090 "$(vedetta_resolve_port VEDETTA_EXPORTED_PORT 8080 "${DOTENV}")" "Compose export assignment"
assert_eq 18091 "$(vedetta_resolve_port VEDETTA_REFERENCED_PORT 8080 "${DOTENV}")" "Compose dotenv reference"
assert_eq 18091 "$(vedetta_resolve_port VEDETTA_DOUBLE_REF 8080 "${DOTENV}")" "double-quoted dotenv reference"
assert_eq 2222 "$(vedetta_resolve_port VEDETTA_DUPLICATE_PORT 1 "${DOTENV}")" "last dotenv assignment wins"
assert_eq 9090 "$(vedetta_resolve_port VEDETTA_MISSING_PORT 9090 "${DOTENV}")" "missing key uses default"

export VEDETTA_BACKEND_PORT=28080
assert_eq 28080 "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${DOTENV}")" "shell environment wins over dotenv"
unset VEDETTA_BACKEND_PORT

export BASE_PORT=28091
assert_eq 28091 "$(vedetta_resolve_port VEDETTA_REFERENCED_PORT 8080 "${DOTENV}")" "shell environment wins for dotenv reference"
unset BASE_PORT
assert_false "single-quoted dotenv reference stays literal" "${BASH}" -c \
  '. "$1"; vedetta_resolve_port VEDETTA_SINGLE_REF 8080 "$2" >/dev/null 2>&1' \
  sh "${REPO_ROOT}/scripts/lib/port-config.sh" "${DOTENV}"
assert_eq 8080 "$(vedetta_resolve_port CYCLE_A 8080 "${DOTENV}")" "unresolved sequential cycle uses Compose default"

SEQUENTIAL_ENV="${TMP_DIR}/sequential.env"
printf '%s\n' \
  'BASE_PORT=18085' \
  'VEDETTA_BACKEND_PORT=${BASE_PORT}' \
  'BASE_PORT=18086' >"${SEQUENTIAL_ENV}"
FORWARD_ENV="${TMP_DIR}/forward.env"
printf '%s\n' \
  'VEDETTA_BACKEND_PORT=${BASE_PORT}' \
  'BASE_PORT=18084' >"${FORWARD_ENV}"
assert_eq 18085 "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${SEQUENTIAL_ENV}")" "dotenv references freeze at assignment time"
assert_eq 8080 "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${FORWARD_ENV}")" "forward dotenv reference uses Compose default"

COMPOSE_FIXTURE="${TMP_DIR}/compose.yml"
printf '%s\n' \
  'services:' \
  '  parity:' \
  '    image: scratch' \
  '    ports:' \
  '      - "${VEDETTA_BACKEND_PORT:-8080}:80"' >"${COMPOSE_FIXTURE}"
compose_port() {
  docker compose -f "${COMPOSE_FIXTURE}" --env-file "$1" config --format json 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["parity"]["ports"][0]["published"])'
}
if command -v docker >/dev/null 2>&1 &&
  docker compose version >/dev/null 2>&1 &&
  command -v python3 >/dev/null 2>&1; then
  assert_eq "$(compose_port "${SEQUENTIAL_ENV}")" "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${SEQUENTIAL_ENV}")" "sequential reference matches Docker Compose"
  assert_eq "$(compose_port "${FORWARD_ENV}")" "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${FORWARD_ENV}")" "forward reference matches Docker Compose"
else
  skip "sequential reference matches Docker Compose (docker compose/python3 unavailable)"
  skip "forward reference matches Docker Compose (docker compose/python3 unavailable)"
fi
export VEDETTA_BACKEND_PORT=
assert_eq 8080 "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${DOTENV}")" "empty shell value uses Compose default"
unset VEDETTA_BACKEND_PORT

export VEDETTA_BACKEND_PORT=70000
assert_false "out-of-range shell port is rejected" "${BASH}" -c \
  '. "$1"; vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "$2" >/dev/null 2>&1' \
  sh "${REPO_ROOT}/scripts/lib/port-config.sh" "${DOTENV}"
unset VEDETTA_BACKEND_PORT
assert_eq 80 "$(vedetta_normalize_port 00080)" "leading zeroes normalize safely"

FAKE_BIN="${TMP_DIR}/bin"
mkdir "${FAKE_BIN}"
printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*"' \
  'i=0; while [ "$i" -lt 5000 ]; do printf "%s\n" "LISTEN 0 128 192.0.2.80:3107 0.0.0.0:*"; i=$((i + 1)); done' >"${FAKE_BIN}/ss"
printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "tcp4 0 0 192.0.2.5.55000 203.0.113.34.8080 ESTABLISHED"' \
  'printf "%s\n" "tcp4 0 0 127.0.0.1.3107 *.* LISTEN"' \
  'printf "%s\n" "udp4 0 0 *.5140 *.*"' >"${FAKE_BIN}/netstat"
printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "p101" "n192.0.2.5:55000->203.0.113.34:8080"' \
  'printf "%s\n" "p102" "n127.0.0.1:3107"' >"${FAKE_BIN}/lsof"
chmod +x "${FAKE_BIN}/ss" "${FAKE_BIN}/netstat" "${FAKE_BIN}/lsof"
PATH="${FAKE_BIN}:${PATH}"

assert_false "ss ignores IP octets" vedetta_port_in_use ss tcp 80
assert_true "ss detects exact local listener" vedetta_port_in_use ss tcp 8080
assert_false "netstat ignores foreign endpoint" vedetta_port_in_use netstat tcp 8080
assert_true "netstat detects local TCP listener" vedetta_port_in_use netstat tcp 3107
assert_true "netstat detects local UDP socket" vedetta_port_in_use netstat udp 5140
assert_false "lsof ignores remote endpoint" vedetta_port_in_use lsof tcp 8080
assert_true "lsof detects exact local endpoint" vedetta_port_in_use lsof tcp 3107
assert_false "lsof UDP ignores remote endpoint" vedetta_port_in_use lsof udp 8080
assert_true "lsof UDP detects exact local endpoint" vedetta_port_in_use lsof udp 3107

BROKEN_BIN="${TMP_DIR}/broken-bin"
mkdir "${BROKEN_BIN}"
printf '%s\n' '#!/bin/sh' 'exit 2' >"${BROKEN_BIN}/lsof"
chmod +x "${BROKEN_BIN}/lsof"
if PATH="${BROKEN_BIN}:${PATH}" vedetta_port_in_use lsof tcp 8080; then
  fail "failing lsof was treated as a successful probe"
else
  probe_status=$?
fi
assert_eq 2 "${probe_status}" "probe command failure has a distinct status"

NO_MATCH_BIN="${TMP_DIR}/no-match-bin"
mkdir "${NO_MATCH_BIN}"
printf '%s\n' '#!/bin/sh' 'exit 1' >"${NO_MATCH_BIN}/lsof"
chmod +x "${NO_MATCH_BIN}/lsof"
if env PATH="${NO_MATCH_BIN}:${PATH}" "${BASH}" -c \
  '. "$1"; vedetta_port_in_use lsof tcp 8080' bash "${REPO_ROOT}/scripts/lib/port-config.sh"; then
  fail "empty lsof status 1 was treated as a positive match"
else
  probe_status=$?
fi
assert_eq 1 "${probe_status}" "empty lsof status 1 is a confirmed no-match"

AMBIGUOUS_BIN="${TMP_DIR}/ambiguous-bin"
mkdir "${AMBIGUOUS_BIN}"
printf '%s\n' '#!/bin/sh' 'echo "lsof: permission denied" >&2' 'exit 1' >"${AMBIGUOUS_BIN}/lsof"
chmod +x "${AMBIGUOUS_BIN}/lsof"
if PATH="${AMBIGUOUS_BIN}:${PATH}" vedetta_port_in_use lsof tcp 8080; then
  fail "lsof status 1 with diagnostics was treated as a successful probe"
else
  probe_status=$?
fi
assert_eq 2 "${probe_status}" "ambiguous lsof status 1 fails closed"

BROKEN_ENV="${TMP_DIR}/broken-probe.env"
if PATH="${BROKEN_BIN}:${PATH}" ENV_FILE="${BROKEN_ENV}" \
  "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/broken.out" 2>"${TMP_DIR}/broken.err"; then
  fail "generator accepted a failed probe command"
fi
[ ! -e "${BROKEN_ENV}" ] || fail "failed probe left an env file"
assert_true "generator explains failed probe" grep -q 'failed while checking' "${TMP_DIR}/broken.err"

AMBIGUOUS_ENV="${TMP_DIR}/ambiguous-probe.env"
if PATH="${AMBIGUOUS_BIN}:${PATH}" ENV_FILE="${AMBIGUOUS_ENV}" \
  "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/ambiguous.out" 2>"${TMP_DIR}/ambiguous.err"; then
  fail "generator accepted an ambiguous lsof status 1"
fi
[ ! -e "${AMBIGUOUS_ENV}" ] || fail "ambiguous probe left an env file"
assert_true "generator reports ambiguous lsof failure" grep -q 'failed while checking' "${TMP_DIR}/ambiguous.err"

OCCUPIED_BIN="${TMP_DIR}/occupied-bin"
mkdir "${OCCUPIED_BIN}"
printf '%s\n' '#!/bin/sh' \
  'case "$*" in' \
  '  *-iTCP:45000*) printf "%s\n" p123 n127.0.0.1:45000; exit 0 ;;' \
  '  *) exit 1 ;;' \
  'esac' >"${OCCUPIED_BIN}/lsof"
chmod +x "${OCCUPIED_BIN}/lsof"
OCCUPIED_ENV="${TMP_DIR}/occupied-export.env"
if PATH="${OCCUPIED_BIN}:${PATH}" VEDETTA_BACKEND_PORT=45000 \
  ENV_FILE="${OCCUPIED_ENV}" "${REPO_ROOT}/scripts/gen-env.sh" \
  >"${TMP_DIR}/occupied.out" 2>"${TMP_DIR}/occupied.err"; then
  fail "generator persisted a shifted occupied port beneath an exported override"
fi
[ ! -e "${OCCUPIED_ENV}" ] || fail "shifted occupied export left an env file"
assert_true "generator rejects an occupied exported preference" grep -q \
  'exported as 45000, but port probing selected 45001' "${TMP_DIR}/occupied.err"

GENERATED_ENV="${TMP_DIR}/generated.env"
if VEDETTA_BACKEND_PORT=41000 VEDETTA_FRONTEND_PORT=41000 \
  ENV_FILE="${GENERATED_ENV}" "${REPO_ROOT}/scripts/gen-env.sh" \
  >"${TMP_DIR}/gen.out" 2>"${TMP_DIR}/gen.err"; then
  fail "generator persisted a shifted port beneath a stale exported override"
fi
[ ! -e "${GENERATED_ENV}" ] || fail "shifted exported port left an env file"
assert_true "generator explains exported-port precedence" grep -q \
  'exported as 41000, but port probing selected 41001' "${TMP_DIR}/gen.err"

if VEDETTA_BACKEND_PORT=70000 ENV_FILE="${TMP_DIR}/invalid.env" \
  "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/invalid.out" 2>"${TMP_DIR}/invalid.err"; then
  fail "generator accepted an invalid port"
fi
[ ! -e "${TMP_DIR}/invalid.env" ] || fail "invalid generator run left an env file"
pass_count=$((pass_count + 1))
echo "ok ${pass_count} - generator rejects invalid ports atomically"

if VEDETTA_SKIP_PORT_PROBE=1 VEDETTA_BACKEND_PORT=42000 VEDETTA_FRONTEND_PORT=42000 \
  ENV_FILE="${TMP_DIR}/duplicate.env" "${REPO_ROOT}/scripts/gen-env.sh" \
  >"${TMP_DIR}/duplicate.out" 2>"${TMP_DIR}/duplicate.err"; then
  fail "generator accepted duplicate TCP ports while probing was skipped"
fi
[ ! -e "${TMP_DIR}/duplicate.env" ] || fail "duplicate generator run left an env file"
pass_count=$((pass_count + 1))
echo "ok ${pass_count} - generator rejects duplicate unprobed TCP ports atomically"

SKIPPED_ENV="${TMP_DIR}/skipped.env"
VEDETTA_SKIP_PORT_PROBE=1 ENV_FILE="${SKIPPED_ENV}" \
  "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/skipped.out"
assert_true "generator labels skipped ports as not probed" grep -q 'Host ports (NOT probed' "${TMP_DIR}/skipped.out"

# Hold two generators at their first openssl call. Both have passed the initial
# destination check before either can install, deterministically exercising the
# final create-if-absent boundary rather than relying on scheduler timing.
REAL_OPENSSL="$(command -v openssl)"
RACE_BIN="${TMP_DIR}/race-bin"
RACE_STATE="${TMP_DIR}/race-state"
RACE_ENV="${TMP_DIR}/concurrent.env"
mkdir "${RACE_BIN}" "${RACE_STATE}"
cat >"${RACE_BIN}/openssl" <<'EOF'
#!/bin/sh
marker="${RACE_STATE}/ready.${RACE_ID}"
if [ ! -e "${marker}" ]; then
  : >"${marker}"
  while [ "$(find "${RACE_STATE}" -name 'ready.*' -type f | wc -l | tr -d ' ')" -lt 2 ]; do
    sleep 0.01
  done
fi
exec "${REAL_OPENSSL}" "$@"
EOF
chmod +x "${RACE_BIN}/openssl"

RACE_ID=a RACE_STATE="${RACE_STATE}" REAL_OPENSSL="${REAL_OPENSSL}" \
  PATH="${RACE_BIN}:${PATH}" VEDETTA_SKIP_PORT_PROBE=1 ENV_FILE="${RACE_ENV}" \
  "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/race-a.out" 2>"${TMP_DIR}/race-a.err" &
race_pid_a=$!
RACE_ID=b RACE_STATE="${RACE_STATE}" REAL_OPENSSL="${REAL_OPENSSL}" \
  PATH="${RACE_BIN}:${PATH}" VEDETTA_SKIP_PORT_PROBE=1 ENV_FILE="${RACE_ENV}" \
  "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/race-b.out" 2>"${TMP_DIR}/race-b.err" &
race_pid_b=$!
race_status_a=0
race_status_b=0
wait "${race_pid_a}" || race_status_a=$?
wait "${race_pid_b}" || race_status_b=$?

race_successes=0
[ "${race_status_a}" -eq 0 ] && race_successes=$((race_successes + 1))
[ "${race_status_b}" -eq 0 ] && race_successes=$((race_successes + 1))
assert_eq 1 "${race_successes}" "concurrent generators have exactly one winner"
assert_true "concurrent generator installs one complete env" test -s "${RACE_ENV}"
if [ "${race_status_a}" -eq 0 ]; then
  race_winner_out="${TMP_DIR}/race-a.out"
  race_loser_err="${TMP_DIR}/race-b.err"
else
  race_winner_out="${TMP_DIR}/race-b.out"
  race_loser_err="${TMP_DIR}/race-a.err"
fi
race_final_code="$(sed -n 's/^VEDETTA_SETUP_CODE=//p' "${RACE_ENV}")"
race_printed_code="$(tail -n 1 "${race_winner_out}" | tr -d '[:space:]')"
assert_eq "${race_final_code}" "${race_printed_code}" "winning setup code matches installed env"
assert_true "concurrent loser reports create-if-absent refusal" grep -q \
  'created by another setup process.*refusing to overwrite' "${race_loser_err}"

# A plain `ln source destination` follows a destination symlink to a directory
# and reports success after putting the secret inside it. Race that path into
# existence after gen-env's initial check and prove the strict link(2) wrapper
# rejects it without leaving a credential link behind.
SYMLINK_RACE_BIN="${TMP_DIR}/symlink-race-bin"
SYMLINK_RACE_STATE="${TMP_DIR}/symlink-race-state"
SYMLINK_RACE_TARGET="${TMP_DIR}/symlink-race-target"
SYMLINK_RACE_ENV="${TMP_DIR}/symlink-race.env"
mkdir "${SYMLINK_RACE_BIN}" "${SYMLINK_RACE_STATE}" "${SYMLINK_RACE_TARGET}"
cat >"${SYMLINK_RACE_BIN}/openssl" <<'EOF'
#!/bin/sh
: >"${SYMLINK_RACE_STATE}/ready"
while [ ! -e "${SYMLINK_RACE_STATE}/release" ]; do
  sleep 0.01
done
exec "${REAL_OPENSSL}" "$@"
EOF
chmod +x "${SYMLINK_RACE_BIN}/openssl"

SYMLINK_RACE_STATE="${SYMLINK_RACE_STATE}" REAL_OPENSSL="${REAL_OPENSSL}" \
  PATH="${SYMLINK_RACE_BIN}:${PATH}" VEDETTA_SKIP_PORT_PROBE=1 ENV_FILE="${SYMLINK_RACE_ENV}" \
  "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/symlink-race.out" 2>"${TMP_DIR}/symlink-race.err" &
symlink_race_pid=$!
while [ ! -e "${SYMLINK_RACE_STATE}/ready" ]; do
  sleep 0.01
done
ln -s "${SYMLINK_RACE_TARGET}" "${SYMLINK_RACE_ENV}"
: >"${SYMLINK_RACE_STATE}/release"
symlink_race_status=0
wait "${symlink_race_pid}" || symlink_race_status=$?

assert_eq 1 "${symlink_race_status}" "raced symlink destination is rejected"
assert_true "raced destination symlink remains unchanged" test -L "${SYMLINK_RACE_ENV}"
assert_false "raced symlink target receives no credential link" sh -c \
  'find "$1" -mindepth 1 -maxdepth 1 -print -quit | grep -q .' sh "${SYMLINK_RACE_TARGET}"
assert_false "raced symlink install reports no success" grep -q '^Wrote ' "${TMP_DIR}/symlink-race.out"

assert_true "update-all waits on local Core readiness after rebuild" grep -Fq \
  '"${LOCAL_CORE_URL}/readyz"' "${REPO_ROOT}/scripts/update-all.sh"
assert_true "update-all preserves the remote sensor Core override" grep -Fq \
  'SENSOR_CORE_URL="${VEDETTA_CORE_URL:-${LOCAL_CORE_URL}}"' "${REPO_ROOT}/scripts/update-all.sh"

echo "1..${pass_count}"
