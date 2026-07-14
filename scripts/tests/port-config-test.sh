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
assert_false "single-quoted dotenv reference stays literal" sh -c \
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
assert_eq "$(compose_port "${SEQUENTIAL_ENV}")" "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${SEQUENTIAL_ENV}")" "sequential reference matches Docker Compose"
assert_eq "$(compose_port "${FORWARD_ENV}")" "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${FORWARD_ENV}")" "forward reference matches Docker Compose"
export VEDETTA_BACKEND_PORT=
assert_eq 8080 "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${DOTENV}")" "empty shell value uses Compose default"
unset VEDETTA_BACKEND_PORT

export VEDETTA_BACKEND_PORT=70000
assert_false "out-of-range shell port is rejected" sh -c \
  '. "$1"; vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "$2" >/dev/null 2>&1' \
  sh "${REPO_ROOT}/scripts/lib/port-config.sh" "${DOTENV}"
unset VEDETTA_BACKEND_PORT
assert_eq 80 "$(vedetta_normalize_port 00080)" "leading zeroes normalize safely"

FAKE_BIN="${TMP_DIR}/bin"
mkdir "${FAKE_BIN}"
printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*"' \
  'i=0; while [ "$i" -lt 5000 ]; do printf "%s\n" "LISTEN 0 128 192.168.1.80:3107 0.0.0.0:*"; i=$((i + 1)); done' >"${FAKE_BIN}/ss"
printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "tcp4 0 0 10.0.0.5.55000 93.184.216.34.8080 ESTABLISHED"' \
  'printf "%s\n" "tcp4 0 0 127.0.0.1.3107 *.* LISTEN"' \
  'printf "%s\n" "udp4 0 0 *.5140 *.*"' >"${FAKE_BIN}/netstat"
printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "p101" "n10.0.0.5:55000->93.184.216.34:8080"' \
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

BROKEN_ENV="${TMP_DIR}/broken-probe.env"
if PATH="${BROKEN_BIN}:${PATH}" ENV_FILE="${BROKEN_ENV}" \
  "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/broken.out" 2>"${TMP_DIR}/broken.err"; then
  fail "generator accepted a failed probe command"
fi
[ ! -e "${BROKEN_ENV}" ] || fail "failed probe left an env file"
assert_true "generator explains failed probe" grep -q 'failed while checking' "${TMP_DIR}/broken.err"

GENERATED_ENV="${TMP_DIR}/generated.env"
VEDETTA_BACKEND_PORT=41000 VEDETTA_FRONTEND_PORT=41000 \
  ENV_FILE="${GENERATED_ENV}" "${REPO_ROOT}/scripts/gen-env.sh" >"${TMP_DIR}/gen.out"
assert_eq 41000 "$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${GENERATED_ENV}")" "generator keeps first selected TCP port"
assert_eq 41001 "$(vedetta_resolve_port VEDETTA_FRONTEND_PORT 3107 "${GENERATED_ENV}")" "generator reserves backend port from frontend"

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

assert_true "update-all checks the local Core after rebuild" grep -Fq \
  'curl -sf "${LOCAL_CORE_URL}/healthz"' "${REPO_ROOT}/scripts/update-all.sh"
assert_true "update-all preserves the remote sensor Core override" grep -Fq \
  'SENSOR_CORE_URL="${VEDETTA_CORE_URL:-${LOCAL_CORE_URL}}"' "${REPO_ROOT}/scripts/update-all.sh"

echo "1..${pass_count}"
