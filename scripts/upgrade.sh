#!/usr/bin/env bash
#
# Vedetta — Trustworthy Core upgrade (backup → migrate → verify → auto-rollback)
#
# Motivated by the 2026-07-13 incident: `docker compose up -d --build` on a
# populated Core DB (15→25 migrations) crash-looped the backend at migration 019
# with NO automatic backup, NO post-migration integrity check, and NO rollback.
#
# This script makes every Core upgrade recoverable:
#
#   1. Snapshot FIRST — the Core DB (+ .env + telemetry/threat-network volumes)
#      before anything is touched. Online `.backup` when the backend is healthy;
#      a cold volume tarball when it is down or crash-looping (the fail-closed
#      backend makes the online path unavailable during an incident).
#   2. Check out a pinned tag/commit and rebuild.
#   3. Bring the stack up.
#   4. Verify: backend health, then `PRAGMA foreign_key_check` (expect 0 rows)
#      and `PRAGMA integrity_check` (expect "ok").
#   5. On ANY failure: stop the backend, restore the pre-upgrade snapshot into
#      the volume, check out the previous version, bring it back up, and exit
#      non-zero with the captured backend log.
#
# Rollback = restore the pre-upgrade snapshot, NOT run an older binary on the
# migrated DB. Migrations 025/026 are forward-only; see
# docs/backup-restore-rollback.md.
#
# Usage:
#   scripts/upgrade.sh [options] [<target-ref>]
#
#   <target-ref>   git tag or commit to upgrade to (e.g. v0.2.0). When omitted,
#                  the CURRENT checkout is rebuilt in place — pair with --from,
#                  or a post-start failure halts after the DB restore (there is
#                  no known-good ref to relaunch; restarting the same checkout
#                  would just re-run the failing migration).
#
# Options:
#   -y, --yes                 Non-interactive; do not prompt before upgrading.
#       --from <ref>          Rollback target (default: HEAD before checkout).
#       --no-cache            Build images with --no-cache.
#       --skip-aux            Do not snapshot telemetry-state / threat-network-data.
#       --prune-on-success    Delete the snapshot after a fully verified upgrade.
#       --health-timeout <s>  Seconds to wait for backend health (default 120).
#   -h, --help                Show this help.
#
set -euo pipefail

# ─── Re-exec from a private copy ──────────────────────────────────────────────
# This script runs `git checkout`, which rewrites tracked files — potentially
# this very file — while bash is still reading it. Re-exec from a temp copy so
# the executing bytes never change underneath us. VEDETTA_UPGRADE_HOME carries
# the real repo root across the exec so lib/ and .env resolve correctly.
if [ -z "${VEDETTA_UPGRADE_SELF:-}" ]; then
  _home="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  _tmp="$(mktemp "${TMPDIR:-/tmp}/vedetta-upgrade.XXXXXX")"
  cat "${BASH_SOURCE[0]}" >"$_tmp"
  export VEDETTA_UPGRADE_SELF="$_tmp"
  export VEDETTA_UPGRADE_HOME="$_home"
  exec bash "$_tmp" "$@"
fi

PROJECT_DIR="${VEDETTA_UPGRADE_HOME}"
SCRIPT_DIR="${PROJECT_DIR}/scripts"

# ─── Output helpers ───────────────────────────────────────────────────────────
step() { printf '\n▸ %s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ⚠ %s\n' "$*" >&2; }
err()  { printf '  ✗ %s\n' "$*" >&2; }

usage() { sed -n '2,43p' "$VEDETTA_UPGRADE_SELF" | sed 's/^# \{0,1\}//'; }

# ─── Args ─────────────────────────────────────────────────────────────────────
ASSUME_YES=0
TARGET_REF=""
FROM_REF=""
NO_CACHE=""
SKIP_AUX=0
PRUNE_ON_SUCCESS=0
HEALTH_TIMEOUT=120

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)          ASSUME_YES=1 ;;
    --from)            shift; FROM_REF="${1:-}" ;;
    --no-cache)        NO_CACHE=1 ;;
    --skip-aux)        SKIP_AUX=1 ;;
    --prune-on-success) PRUNE_ON_SUCCESS=1 ;;
    --health-timeout)  shift; HEALTH_TIMEOUT="${1:-120}" ;;
    -h|--help)         usage; exit 0 ;;
    --)                shift; break ;;
    -*)                err "unknown option: $1"; usage; exit 2 ;;
    *)                 if [ -z "$TARGET_REF" ]; then TARGET_REF="$1"; else err "unexpected argument: $1"; exit 2; fi ;;
  esac
  shift
done
if [ $# -gt 0 ] && [ -z "$TARGET_REF" ]; then TARGET_REF="$1"; fi
case "$HEALTH_TIMEOUT" in ''|*[!0-9]*) err "--health-timeout must be an integer"; exit 2 ;; esac

# Resolve host ports the way Docker Compose does, WITHOUT sourcing secret-bearing
# .env. Loaded now, before any checkout, so the functions survive a tree swap.
# shellcheck source=scripts/lib/port-config.sh
source "${SCRIPT_DIR}/lib/port-config.sh"
BACKEND_PORT="$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${PROJECT_DIR}/.env")"

cd "$PROJECT_DIR"

# ─── Cleanup ──────────────────────────────────────────────────────────────────
cleanup() {
  local rc=$?
  [ -n "${VEDETTA_UPGRADE_SELF:-}" ] && rm -f "$VEDETTA_UPGRADE_SELF" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

# ─── Docker / Compose helpers ────────────────────────────────────────────────
detect_project() {
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then printf '%s' "$COMPOSE_PROJECT_NAME"; return; fi
  local cid p
  cid="$(docker compose ps -aq 2>/dev/null | head -n1 || true)"
  if [ -n "$cid" ]; then
    p="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' "$cid" 2>/dev/null || true)"
    [ -n "$p" ] && { printf '%s' "$p"; return; }
  fi
  basename "$PROJECT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-'
}

# resolve_volume <compose-key> — print the real (project-prefixed) volume name.
# Accepts ONLY an exact "${PROJECT}_<key>" match or a single unambiguous
# candidate. Never guesses between multiple matches: on a host running more
# than one Vedetta stack, picking "the first one" could snapshot — and later
# RESTORE over — another installation's database. Returns 1 when it cannot
# decide; the caller surfaces the candidates.
resolve_volume() {
  local key="$1" labeled name count
  labeled="$(docker volume ls --filter "label=com.docker.compose.volume=${key}" \
             --format '{{.Name}}' 2>/dev/null || true)"
  # Exact project-prefixed match wins outright.
  if [ -n "${PROJECT:-}" ] && printf '%s\n' "$labeled" | grep -Fxq "${PROJECT}_${key}"; then
    printf '%s' "${PROJECT}_${key}"; return 0
  fi
  count="$(printf '%s' "$labeled" | grep -c . || true)"
  if [ "$count" = "1" ]; then printf '%s' "$labeled"; return 0; fi
  [ "$count" != "0" ] && return 1   # several projects own a <key> volume — ambiguous
  # No labeled candidates (e.g. volume created outside Compose): accept a
  # uniquely-named fallback only.
  name="$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E "(^|_)${key}$" || true)"
  if [ "$(printf '%s' "$name" | grep -c . || true)" = "1" ]; then printf '%s' "$name"; return 0; fi
  return 1
}

volume_exists() { docker volume inspect "$1" >/dev/null 2>&1; }
backend_running() { [ -n "$(docker compose ps -q backend 2>/dev/null)" ]; }

wait_health() {
  local timeout="$1" i
  for ((i = 0; i < timeout; i++)); do
    if curl -fsS -m 3 "http://127.0.0.1:${BACKEND_PORT}/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

# ─── Preflight (nothing changed yet — plain exits, no rollback) ───────────────
command -v docker >/dev/null 2>&1 || { err "docker not found on PATH."; exit 2; }
command -v curl   >/dev/null 2>&1 || { err "curl not found on PATH."; exit 2; }
docker compose version >/dev/null 2>&1 || { err "docker compose v2 is required."; exit 2; }
git rev-parse --git-dir >/dev/null 2>&1 || { err "not a git repository: $PROJECT_DIR"; exit 2; }

# Only uncommitted changes to TRACKED files block checkout; untracked files
# (operator notes, older checkouts without backups/ in .gitignore) must not
# false-positive. Refresh the stat cache first so stale mtimes don't either.
git update-index -q --refresh 2>/dev/null || true
if ! git diff-index --quiet HEAD --; then
  err "working tree has uncommitted changes — commit or stash them first."
  err "(the upgrade and its rollback both run 'git checkout', which needs a clean tree.)"
  exit 2
fi

PREV_REF="$(git rev-parse HEAD)"
PREV_DESC="$(git describe --tags --always 2>/dev/null || echo "$PREV_REF")"
if [ -n "$FROM_REF" ]; then
  PREV_REF="$(git rev-parse --verify --quiet "${FROM_REF}^{commit}" || true)"
  [ -n "$PREV_REF" ] || { err "--from ref not found: ${FROM_REF}"; exit 2; }
  PREV_DESC="$FROM_REF"
fi

if [ -n "$TARGET_REF" ]; then
  git fetch --tags --quiet 2>/dev/null || warn "git fetch failed; using local refs only."
  git rev-parse --verify --quiet "${TARGET_REF}^{commit}" >/dev/null \
    || { err "target ref not found: ${TARGET_REF}"; exit 2; }
  TARGET_DESC="$TARGET_REF"
else
  TARGET_DESC="${PREV_DESC} (rebuild in place)"
fi

PROJECT="$(detect_project)"
VOL_DATA="$(resolve_volume vedetta-data || true)"
if [ -z "$VOL_DATA" ]; then
  err "Could not resolve the vedetta-data volume for this stack (missing, or"
  err "AMBIGUOUS — more than one Compose project on this host owns one; refusing"
  err "to guess, since restoring into the wrong project would destroy its data)."
  err "Candidates:"; docker volume ls --format '    {{.Name}}' | grep -i vedetta >&2 || true
  err "Bring the stack up once (docker compose up -d) or set COMPOSE_PROJECT_NAME, then retry."
  exit 2
fi

# ─── Snapshot workspace + full transcript ─────────────────────────────────────
TS="$(date +%Y%m%d-%H%M%S)"
SNAP_DIR="${PROJECT_DIR}/backups/upgrade-${TS}"
LOG="${SNAP_DIR}/upgrade-${TS}.log"
# The snapshot holds the live DB, API tokens, and .env — owner-only from the
# very first byte, not only at the post-snapshot chmod (which an interrupted
# run would never reach).
umask 077
mkdir -p "$SNAP_DIR"
chmod 700 "$SNAP_DIR"
# Tee everything (stdout + stderr) into the snapshot dir so a failed upgrade
# leaves a complete transcript next to the backup it can be restored from.
exec > >(tee -a "$LOG") 2>&1

SNAPSHOT_DONE=0
NEW_STACK_UP=0        # the upgraded stack was started (DB may be migrated)
STACK_WAS_STOPPED=0   # we took the previously-running stack down ourselves
CODE_CHANGED=0        # we moved the working tree to TARGET_REF
SNAP_MODE=""
SNAP_ARTIFACT=""
FAILED=0

# ─── Failure + rollback machinery ─────────────────────────────────────────────
restore_main_volume() {
  case "$SNAP_MODE" in
    online)
      # Restore the single pre-upgrade DB file; delete any WAL/SHM left by the
      # failed new backend so SQLite cannot replay migrated frames onto it.
      # Preserve the DB file's ownership (cp in the helper container runs as
      # root; a non-root backend could no longer open a root-owned DB).
      docker run --rm -v "${VOL_DATA}:/data" -v "${SNAP_DIR}:/backup:ro" alpine \
        sh -ec 'owner="$(stat -c %u:%g /data/vedetta.db 2>/dev/null || stat -c %u:%g /data)"
                rm -f /data/vedetta.db /data/vedetta.db-wal /data/vedetta.db-shm
                cp "/backup/$1" /data/vedetta.db
                chown "$owner" /data/vedetta.db' _ "$(basename "$SNAP_ARTIFACT")"
      ;;
    cold)
      docker run --rm -v "${VOL_DATA}:/data" -v "${SNAP_DIR}:/backup:ro" alpine \
        sh -ec 'rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true
                tar xzf "/backup/$1" -C /data' _ "$(basename "$SNAP_ARTIFACT")"
      ;;
    *) return 1 ;;
  esac
}

# halt_rollback <why> — a rollback step failed in a way where STARTING ANYTHING
# is the dangerous move (volume not restored, or the compose image is still the
# bad upgraded build). Leave the stack DOWN with the snapshot intact and tell
# the operator exactly where they stand. Never falls through to `up -d`.
halt_rollback() {
  err "ROLLBACK HALTED: $1"
  err "The stack is left STOPPED on purpose — starting a container here could run"
  err "the wrong code against the wrong schema and corrupt the remaining good copy."
  err "Your pre-upgrade snapshot is intact at: ${SNAP_ARTIFACT}"
  err "Recover manually with docs/backup-restore-rollback.md (sections 2 and 4)."
}

do_rollback() {
  local fail_head
  fail_head="$(git rev-parse HEAD)"
  warn "Rolling back to ${PREV_DESC} and restoring the pre-upgrade snapshot…"

  { echo "----- backend logs at failure ($(date +%H:%M:%S)) -----"
    docker compose logs --no-color --tail=200 backend 2>&1 || true
  } >>"$LOG"

  # Failure BEFORE the stack was modified (e.g. the target build failed while
  # the old stack kept serving): nothing was stopped and nothing ran, so don't
  # cause downtime by tearing down a healthy stack. Just restore the tree if
  # the script had moved it.
  if [ "$NEW_STACK_UP" != "1" ] && [ "$STACK_WAS_STOPPED" != "1" ]; then
    if [ "$CODE_CHANGED" = "1" ]; then
      if git checkout --quiet "$PREV_REF"; then ok "Restored working tree to ${PREV_DESC}."
      else
        halt_rollback "git checkout ${PREV_DESC} failed — the tree still holds the target version"
        return 1
      fi
    fi
    ok "The running stack was never touched — it stays up as-is."
    return 0
  fi

  docker compose down || warn "docker compose down reported an error; continuing."

  if [ "$NEW_STACK_UP" = "1" ]; then
    if restore_main_volume; then ok "Restored Core DB from the pre-upgrade snapshot."
    else
      # The volume may still hold the migrated/corrupt DB. Booting ANY version
      # against it is exactly what this script exists to prevent.
      halt_rollback "could not restore the snapshot into the ${VOL_DATA} volume"
      return 1
    fi
  else
    warn "The new version never started; the DB was not migrated — leaving data as-is."
  fi

  # From here the DB is pre-upgrade again, but the compose image is still the
  # BAD upgraded build until a KNOWN-GOOD ref is checked out AND rebuilt. If
  # any step fails, `up -d` would relaunch the bad image against the restored
  # data and re-run the failing migrations — halt instead.
  if [ "$PREV_REF" != "$fail_head" ]; then
    # Covers both the normal target-ref flow and --from in rebuild-in-place
    # mode (where the tree never moved but the operator named a good ref).
    if ! git checkout --quiet "$PREV_REF"; then
      halt_rollback "git checkout ${PREV_DESC} failed — the tree still holds the failed version"
      return 1
    fi
  elif [ "$NEW_STACK_UP" = "1" ]; then
    # Rebuild-in-place with no --from: the failing version IS the current
    # checkout. Restarting it would immediately re-run the failing migration
    # against the just-restored DB, undoing the rollback.
    halt_rollback "the failed version is the current checkout — restarting it would re-run the failing migration (re-run with --from <known-good-ref> to enable automatic rollback)"
    return 1
  fi
  if ! docker compose build ${NO_CACHE:+--no-cache}; then
    halt_rollback "rebuild of the previous version failed — the compose image is still the upgraded build"
    return 1
  fi
  docker compose up -d || { halt_rollback "docker compose up -d failed for the previous version"; return 1; }

  if wait_health 60; then ok "Previous version is back up and healthy at ${PREV_DESC}."
  else err "Previous version did not become healthy within 60s — check: docker compose logs backend"; fi
}

fail() {
  local msg="$*"
  if [ "$FAILED" = "1" ]; then err "nested failure while recovering: $msg"; exit 1; fi
  FAILED=1
  trap - ERR
  set +e
  err "UPGRADE FAILED: $msg"
  if [ "$SNAPSHOT_DONE" = "1" ]; then
    do_rollback
  else
    err "No snapshot was taken yet; the stack was not modified — nothing to roll back."
  fi
  echo ""
  err "Details, snapshot, and full transcript: ${SNAP_DIR}"
  exit 1
}

# ─── Plan + confirm ───────────────────────────────────────────────────────────
cat <<EOF

═══════════════════════════════════════════════════════════
  Vedetta Core — safe upgrade
═══════════════════════════════════════════════════════════
  Compose project:   ${PROJECT}
  Data volume:       ${VOL_DATA}
  Current version:   ${PREV_DESC}
  Target version:    ${TARGET_DESC}
  Snapshot dir:      ${SNAP_DIR}
  Health URL:        http://127.0.0.1:${BACKEND_PORT}/healthz
───────────────────────────────────────────────────────────
  Steps: snapshot (DB + .env + aux volumes) → checkout → build →
  up → verify (health, foreign_key_check, integrity_check).
  On ANY failure the pre-upgrade snapshot is restored and the
  stack returns to ${PREV_DESC}.
═══════════════════════════════════════════════════════════
EOF

if [ "$ASSUME_YES" != "1" ]; then
  if [ ! -t 0 ]; then
    err "Refusing to run non-interactively without --yes (stdin is not a TTY)."
    exit 2
  fi
  printf '  Proceed with the upgrade? [y/N] '
  read -r _reply
  case "$_reply" in y|Y|yes|YES) ;; *) echo "  Aborted — nothing was changed."; exit 0 ;; esac
fi

# ─── 1. Snapshot FIRST ────────────────────────────────────────────────────────
step "Snapshotting before any change…"

if backend_running && wait_health 5; then
  ok "Backend is healthy — taking an online .backup (no downtime)."
  SNAP_ARTIFACT="${SNAP_DIR}/vedetta-db-pre-${TS}.db"
  docker compose exec -T backend sqlite3 /data/vedetta.db ".backup '/data/pre-${TS}.db'" \
    || fail "online .backup failed"
  # Plain `docker cp` (not `docker compose cp`, which needs Compose >= 2.20),
  # and clean the in-container temp file up on BOTH exits so a failed copy
  # doesn't leave a full DB copy eating the data volume.
  if ! docker cp "$(docker compose ps -q backend | head -n1):/data/pre-${TS}.db" "$SNAP_ARTIFACT"; then
    docker compose exec -T backend rm -f "/data/pre-${TS}.db" 2>/dev/null || true
    fail "copying the snapshot out of the container failed"
  fi
  docker compose exec -T backend rm -f "/data/pre-${TS}.db" \
    || warn "could not remove the in-container temp snapshot (harmless)."
  SNAP_MODE="online"
else
  warn "Backend is not healthy — stopping the stack for a cold volume snapshot."
  STACK_WAS_STOPPED=1
  docker compose down || warn "docker compose down reported an error; continuing."
  SNAP_ARTIFACT="${SNAP_DIR}/vedetta-data-${TS}.tar.gz"
  # chown the tarball to the invoking host user — the helper container runs as
  # root, and a root-owned backup would need sudo to manage or prune later.
  docker run --rm -v "${VOL_DATA}:/data:ro" -v "${SNAP_DIR}:/backup" alpine \
    sh -ec 'tar czf "/backup/$1" -C /data . && chown "$2" "/backup/$1"' \
    _ "$(basename "$SNAP_ARTIFACT")" "$(id -u):$(id -g)" \
    || fail "cold volume snapshot failed"
  SNAP_MODE="cold"
fi
ok "Core DB snapshot: $(basename "$SNAP_ARTIFACT") (${SNAP_MODE})"

# .env sits outside the volume; capture it too (it holds deployment secrets).
if [ -f "${PROJECT_DIR}/.env" ]; then
  cp -p "${PROJECT_DIR}/.env" "${SNAP_DIR}/env-${TS}.bak" && ok "Copied .env → env-${TS}.bak"
else
  warn "No .env next to docker-compose.yml — skipping .env backup."
fi

# Auxiliary volumes (cold tarball; best-effort — the Core DB is what matters).
if [ "$SKIP_AUX" != "1" ]; then
  for key in telemetry-state threat-network-data; do
    vol="$(resolve_volume "$key" || true)"
    if [ -n "$vol" ] && volume_exists "$vol"; then
      out="${key}-${TS}.tar.gz"
      if docker run --rm -v "${vol}:/data:ro" -v "${SNAP_DIR}:/backup" alpine \
           sh -ec 'tar czf "/backup/$1" -C /data . && chown "$2" "/backup/$1"' \
           _ "${out}" "$(id -u):$(id -g)"; then
        ok "Snapshotted ${key} → ${out}"
      else
        warn "Could not snapshot ${key} (continuing; auxiliary volume)."
      fi
    else
      warn "No ${key} volume present — skipping."
    fi
  done
fi

SNAPSHOT_DONE=1
chmod -R go-rwx "$SNAP_DIR" 2>/dev/null || true   # snapshots hold DB + tokens + .env
# From here on, any unexpected command failure triggers rollback.
trap 'fail "unexpected error near line ${LINENO}"' ERR

# ─── 2. Check out target + build ──────────────────────────────────────────────
if [ -n "$TARGET_REF" ]; then
  step "Checking out ${TARGET_REF}…"
  git checkout --quiet "$TARGET_REF" || fail "git checkout ${TARGET_REF} failed"
  CODE_CHANGED=1
else
  step "No target ref given — rebuilding the current checkout in place."
fi

step "Building images${NO_CACHE:+ (--no-cache)}…"
docker compose build ${NO_CACHE:+--no-cache} || fail "docker compose build failed"

# ─── 3. Bring the stack up ────────────────────────────────────────────────────
step "Starting the upgraded stack…"
NEW_STACK_UP=1
docker compose up -d || fail "docker compose up -d failed"

# ─── 4. Verify ────────────────────────────────────────────────────────────────
step "Waiting up to ${HEALTH_TIMEOUT}s for the backend to become healthy…"
wait_health "$HEALTH_TIMEOUT" || fail "backend did not become healthy within ${HEALTH_TIMEOUT}s (migration crash-loop?)"
ok "Backend healthy."

step "Verifying database integrity…"
# NB: set the busy timeout with the SILENT `.timeout` dot-command, not an inline
# `PRAGMA busy_timeout=…;` — that PRAGMA echoes its value as an output row, which
# would look like a foreign_key_check violation and roll back every upgrade.
fk="$(docker compose exec -T backend sqlite3 -batch -cmd '.timeout 5000' /data/vedetta.db \
      'PRAGMA foreign_key_check;' 2>>"$LOG")" \
  || fail "could not run PRAGMA foreign_key_check on the upgraded DB"
if [ -n "$fk" ]; then
  err "foreign_key_check reported violations:"; printf '%s\n' "$fk" | sed 's/^/    /' >&2
  fail "post-upgrade foreign_key_check found violations"
fi
ok "foreign_key_check: clean (0 rows)."

integ="$(docker compose exec -T backend sqlite3 -batch -cmd '.timeout 5000' /data/vedetta.db \
        'PRAGMA integrity_check;' 2>>"$LOG")" \
  || fail "could not run PRAGMA integrity_check on the upgraded DB"
if [ "$(printf '%s' "$integ" | tr -d '[:space:]')" != "ok" ]; then
  err "integrity_check reported problems:"; printf '%s\n' "$integ" | sed 's/^/    /' >&2
  fail "post-upgrade integrity_check did not return ok"
fi
ok "integrity_check: ok."

# ─── Success ──────────────────────────────────────────────────────────────────
trap - ERR
cat <<EOF

═══════════════════════════════════════════════════════════
  ✓ Core upgraded to ${TARGET_DESC} and verified.
      • backend healthy
      • foreign_key_check clean
      • integrity_check ok
═══════════════════════════════════════════════════════════
EOF

if [ "$PRUNE_ON_SUCCESS" = "1" ]; then
  cd "$PROJECT_DIR"
  rm -rf "$SNAP_DIR" && echo "  ✓ Pruned snapshot (--prune-on-success)."
else
  ok "Pre-upgrade snapshot kept at: ${SNAP_DIR}"
  ok "It contains your DB, .env, and API tokens — treat it as sensitive and keep"
  ok "it until you have confirmed the new version in daily use."
fi
