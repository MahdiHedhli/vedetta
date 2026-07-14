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
#   1. Snapshot the Core DB (+ .env + telemetry/threat-network volumes) BEFORE
#      the database can change. Healthy backend: the old stack keeps serving
#      through checkout+build and an online `.backup` is taken seconds before
#      the container swap, so a rollback discards almost nothing. Backend down
#      or crash-looping: the stack is stopped and a cold volume tarball is
#      taken FIRST (the fail-closed backend makes the online path unavailable
#      during an incident).
#   2. Check out a pinned tag/commit and rebuild.
#   3. Bring the upgraded stack up.
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
set -Eeuo pipefail
# -E (errtrace): the ERR trap must be inherited by functions and subshells,
# or a failure inside one would bypass fail()/rollback and die under plain -e.

# ─── Re-exec from a private copy ──────────────────────────────────────────────
# This script runs `git checkout`, which rewrites tracked files — potentially
# this very file — while bash is still reading it. Re-exec from a temp copy so
# the executing bytes never change underneath us. VEDETTA_UPGRADE_HOME carries
# the real repo root across the exec so lib/ and .env resolve correctly.
if [ -z "${VEDETTA_UPGRADE_SELF:-}" ]; then
  _home="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  _tmp="$(mktemp "${TMPDIR:-/tmp}/vedetta-upgrade.XXXXXX")"
  # Don't leak the temp copy if anything below fails under set -e. A successful
  # exec replaces this process (trap and all); the child re-registers its own
  # EXIT cleanup for the same file further down.
  trap 'rm -f "$_tmp" 2>/dev/null' EXIT
  cat "${BASH_SOURCE[0]}" >"$_tmp"
  export VEDETTA_UPGRADE_SELF="$_tmp"
  export VEDETTA_UPGRADE_HOME="$_home"
  # "$BASH": re-exec with the SAME interpreter (macOS system bash 3.2 vs a
  # Homebrew bash on PATH can differ in behavior).
  exec "$BASH" "$_tmp" "$@"
fi

PROJECT_DIR="${VEDETTA_UPGRADE_HOME}"
SCRIPT_DIR="${PROJECT_DIR}/scripts"

# Registered FIRST thing in the child: even an exit during argument parsing
# (--help, a bad flag) must remove the re-exec temp copy.
cleanup() {
  local rc=$?
  [ -n "${VEDETTA_UPGRADE_SELF:-}" ] && rm -f "$VEDETTA_UPGRADE_SELF" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

# Under sudo, run git as the invoking user (mirrors scripts/update-all.sh):
# a root git in a user-owned repository fails with "dubious ownership".
git() {
  if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" = "0" ]; then
    command sudo -u "$SUDO_USER" git "$@"
  else
    command git "$@"
  fi
}

# Helper image for volume snapshot/restore one-off containers. Pinned to the
# same Alpine the Dockerfiles use — an untagged `alpine` resolves to :latest
# and `docker run` would PULL it mid-rollback on a host that only has the
# compose base cached; a registry hiccup at that moment would strand the
# restore. Preflighted below before anything is touched.
HELPER_IMAGE="${VEDETTA_HELPER_IMAGE:-alpine:3.24}"

# ─── Output helpers ───────────────────────────────────────────────────────────
step() { printf '\n▸ %s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ⚠ %s\n' "$*" >&2; }
err()  { printf '  ✗ %s\n' "$*" >&2; }

# Print the contiguous header comment block (everything until the first
# non-comment line) — no hardcoded line numbers to fall out of date.
usage() { awk 'NR < 2 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$VEDETTA_UPGRADE_SELF"; }

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
    --from)            [ $# -ge 2 ] || { err "--from requires an argument"; exit 2; }
                       shift; FROM_REF="$1" ;;
    --no-cache)        NO_CACHE=1 ;;
    --skip-aux)        SKIP_AUX=1 ;;
    --prune-on-success) PRUNE_ON_SUCCESS=1 ;;
    --health-timeout)  [ $# -ge 2 ] || { err "--health-timeout requires an argument"; exit 2; }
                       shift; HEALTH_TIMEOUT="$1" ;;
    -h|--help)         usage; exit 0 ;;
    --)                shift; break ;;
    -*)                err "unknown option: $1"; usage; exit 2 ;;
    *)                 if [ -z "$TARGET_REF" ]; then TARGET_REF="$1"; else err "unexpected argument: $1"; exit 2; fi ;;
  esac
  shift
done
# Arguments after `--`: at most one (the target ref); reject silent extras.
if [ $# -gt 0 ]; then
  if [ -z "$TARGET_REF" ]; then TARGET_REF="$1"; shift; fi
  if [ $# -gt 0 ]; then err "unexpected argument: $1"; exit 2; fi
fi
case "$HEALTH_TIMEOUT" in ''|*[!0-9]*) err "--health-timeout must be an integer"; exit 2 ;; esac

# Resolve host ports the way Docker Compose does, WITHOUT sourcing secret-bearing
# .env. Loaded now, before any checkout, so the functions survive a tree swap.
# shellcheck source=scripts/lib/port-config.sh
source "${SCRIPT_DIR}/lib/port-config.sh"
BACKEND_PORT="$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "${PROJECT_DIR}/.env")"

cd "$PROJECT_DIR"

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
# Accepts ONLY a volume that belongs to the SAME Compose project the compose
# commands in this script will control. A looser match (sole candidate on the
# host, name-suffix guess) could pass while `docker compose down/up` targets a
# different — possibly empty — project: the cold path would then fail to stop
# the real backend, and rollback would restore INTO the live install's volume
# while its containers keep writing. Returns 1 when it cannot prove the match;
# the caller surfaces the candidates.
resolve_volume() {
  local key="$1" labeled vol_project
  labeled="$(docker volume ls --filter "label=com.docker.compose.volume=${key}" \
             --format '{{.Name}}' 2>/dev/null || true)"
  # Exact project-prefixed name — the volume Compose itself would use.
  if [ -n "${PROJECT:-}" ] && printf '%s\n' "$labeled" | grep -Fxq "${PROJECT}_${key}"; then
    printf '%s' "${PROJECT}_${key}"; return 0
  fi
  # A sole labeled candidate still must belong to OUR project (covers volumes
  # with custom external names); a different project label means the compose
  # commands would not be operating on the stack that owns this data.
  if [ "$(printf '%s\n' "$labeled" | grep -c . || true)" = "1" ]; then
    vol_project="$(docker volume inspect \
      -f '{{ index .Labels "com.docker.compose.project" }}' "$labeled" 2>/dev/null || true)"
    if [ -n "${PROJECT:-}" ] && [ "$vol_project" = "$PROJECT" ]; then
      printf '%s' "$labeled"; return 0
    fi
    return 1
  fi
  [ -n "$labeled" ] && return 1   # several projects own a <key> volume — ambiguous
  # Unlabeled fallback (volume pre-created outside Compose): accept only the
  # exact name Compose resolves for this project.
  if [ -n "${PROJECT:-}" ] && docker volume inspect "${PROJECT}_${key}" >/dev/null 2>&1; then
    printf '%s' "${PROJECT}_${key}"; return 0
  fi
  return 1
}

volume_exists() { docker volume inspect "$1" >/dev/null 2>&1; }
backend_running() { [ -n "$(docker compose ps --filter status=running -q backend 2>/dev/null)" ]; }

# This is a CORE upgrade: never touch profile-gated services (the community
# threat-network keeps its own data, migrations, and runbook). core_services
# resolves the profile-less service set FRESH from the current checkout — the
# set can legitimately differ between the target and previous refs. With
# COMPOSE_PROFILES forced empty, `config --services` lists exactly the
# services a bare `docker compose up` would manage for a default install.
# NB: no mapfile/arrays-from-stream here — macOS ships bash 3.2 and this
# script must run there. Compose service names cannot contain whitespace, so
# plain word-splitting of the newline-separated list is safe.
# (stderr NOT silenced: a broken docker-compose.yml should show its parse
# error, not surface as a generic "no services" failure.)
core_services() { COMPOSE_PROFILES="" docker compose config --services; }

compose_stop_core() {
  local svcs
  svcs="$(core_services)" && [ -n "$svcs" ] || return 1
  # shellcheck disable=SC2086 # intentional split on whitespace-free names
  docker compose stop $svcs
}
compose_build_core() {
  local svcs
  svcs="$(core_services)" && [ -n "$svcs" ] || return 1
  # shellcheck disable=SC2086 # NO_CACHE is one flag or nothing; names split intentionally
  docker compose build ${NO_CACHE:+--no-cache} $svcs
}
compose_up_core() {
  local svcs
  svcs="$(core_services)" && [ -n "$svcs" ] || return 1
  # shellcheck disable=SC2086 # intentional split on whitespace-free names
  docker compose up -d $svcs
}

# stop_volume_users — stop EVERY container that mounts the Core data volume,
# regardless of service name. compose stop only knows the CURRENT checkout's
# service names; a target ref that renamed or removed a service can leave an
# old-name container running with vedetta-data still mounted — snapshotting
# or restoring under a live writer is exactly what must never happen.
stop_volume_users() {
  local ids
  ids="$(docker ps -q --filter "volume=${VOL_DATA}" 2>/dev/null)" || return 1
  [ -z "$ids" ] && return 0
  # shellcheck disable=SC2086 # container ids are whitespace-free
  docker stop $ids >/dev/null
}
# volume_still_mounted — true if any running container still has the volume.
volume_still_mounted() { [ -n "$(docker ps -q --filter "volume=${VOL_DATA}" 2>/dev/null)" ]; }

# remove_temp_backup — delete the in-volume online-backup temp file. `exec`
# needs a RUNNING backend; if it crashed/restarted between the copy and this
# cleanup, fall back to a helper container mounting the volume — otherwise a
# full copy of the live DB silently stays behind, keeping the volume full.
remove_temp_backup() {
  docker compose exec -T backend rm -f "/data/pre-${TS}.db" 2>/dev/null \
    || docker run --rm -v "${VOL_DATA}:/data" "$HELPER_IMAGE" rm -f "/data/pre-${TS}.db" 2>/dev/null
}

wait_health() {
  local timeout="$1" i
  # 10#: force base-10 — a leading-zero timeout (e.g. "08") would otherwise be
  # parsed as octal and crash the arithmetic context.
  for ((i = 0; i < 10#$timeout; i++)); do
    if curl -fsS -m 3 "http://127.0.0.1:${BACKEND_PORT}/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

# ─── Preflight (nothing changed yet — plain exits, no rollback) ───────────────
command -v docker >/dev/null 2>&1 || { err "docker not found on PATH."; exit 2; }
command -v curl   >/dev/null 2>&1 || { err "curl not found on PATH."; exit 2; }
# type -P: find the git BINARY — command -v would match our git() sudo wrapper.
type -P git       >/dev/null 2>&1 || { err "git not found on PATH."; exit 2; }
docker compose version >/dev/null 2>&1 || { err "docker compose v2 is required."; exit 2; }
git rev-parse --git-dir >/dev/null 2>&1 || { err "not a git repository: $PROJECT_DIR"; exit 2; }

# Ensure the snapshot/restore helper image is local NOW — never mid-rollback.
if ! docker image inspect "$HELPER_IMAGE" >/dev/null 2>&1; then
  echo "  Pulling helper image ${HELPER_IMAGE} (needed for snapshot/restore)…"
  docker pull "$HELPER_IMAGE" >/dev/null \
    || { err "could not pull ${HELPER_IMAGE} — refusing to start an upgrade whose rollback needs it."; exit 2; }
fi

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
# Prefer the symbolic name for the rollback checkout so an operator who was on
# a branch is returned TO that branch, not to a detached HEAD at the same
# commit. Falls back to the hash when already detached.
PREV_BRANCH="$(git symbolic-ref -q --short HEAD || echo "$PREV_REF")"
PREV_DESC="$(git describe --tags --always 2>/dev/null || echo "$PREV_REF")"
if [ -n "$FROM_REF" ]; then
  PREV_REF="$(git rev-parse --verify --quiet "${FROM_REF}^{commit}" || true)"
  [ -n "$PREV_REF" ] || { err "--from ref not found: ${FROM_REF}"; exit 2; }
  PREV_DESC="$FROM_REF"
  PREV_BRANCH="$FROM_REF"
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
# Pin EVERY subsequent compose command to this project. Without the export, a
# target ref that sets a top-level `name:` in docker-compose.yml would flip
# the project mid-run after checkout — compose would then boot a fresh, EMPTY
# vedetta-data under the new project name, pass health and integrity checks,
# and report success while the real data sat stranded in the old project.
# COMPOSE_PROJECT_NAME takes precedence over the file's `name:` key.
export COMPOSE_PROJECT_NAME="$PROJECT"
VOL_DATA="$(resolve_volume vedetta-data || true)"
if [ -z "$VOL_DATA" ]; then
  err "Could not resolve the vedetta-data volume for Compose project '${PROJECT}'"
  err "(missing, owned by a DIFFERENT project, or ambiguous between projects)."
  err "Refusing to guess: compose commands would target '${PROJECT}' while the"
  err "snapshot/restore touched another install's live data."
  err "Candidates:"; docker volume ls --format '    {{.Name}}' | grep -i vedetta >&2 || true
  err "If this install uses a custom project name, export COMPOSE_PROJECT_NAME=<name>"
  err "(check: docker volume inspect -f '{{ index .Labels \"com.docker.compose.project\" }}' <volume>)"
  err "or bring the stack up once (docker compose up -d), then retry."
  exit 2
fi

# ─── Snapshot workspace + full transcript ─────────────────────────────────────
TS="$(date +%Y%m%d-%H%M%S)"
# Snapshots default OUTSIDE the repository: the repo root is the backend build
# context AND `git checkout <ref>` swaps .dockerignore with it, so an in-repo
# location would rely on every target ref knowing to exclude it — an older ref
# would happily ship the DB + env-*.bak into the Docker build cache. A sibling
# directory can never enter a build context or be touched by checkouts.
BACKUP_ROOT="${VEDETTA_BACKUP_DIR:-$(dirname "$PROJECT_DIR")/vedetta-backups}"
# Enforce the invariant even against an explicit override: resolve to an
# absolute path and refuse anything inside the repository — a later
# `git checkout <older-ref>` swaps .dockerignore away and the next build
# would ship the snapshot's secrets into the BuildKit cache.
mkdir -p "$BACKUP_ROOT" || { err "cannot create backup directory: ${BACKUP_ROOT}"; exit 2; }
# pwd -P on BOTH sides: compare PHYSICAL paths — a symlinked backup dir that
# points into the repo would pass a logical-path comparison.
BACKUP_ROOT="$(cd "$BACKUP_ROOT" && pwd -P)"
PROJECT_DIR_PHYS="$(cd "$PROJECT_DIR" && pwd -P)"
case "${BACKUP_ROOT}/" in
  "${PROJECT_DIR_PHYS}/"*)
    err "VEDETTA_BACKUP_DIR resolves inside the repository (${BACKUP_ROOT})."
    err "Snapshots hold your DB and API tokens; inside the repo they can enter"
    err "Docker build contexts after a checkout to a ref whose .dockerignore"
    err "predates the exclusion. Choose a location outside ${PROJECT_DIR}."
    rmdir "$BACKUP_ROOT" 2>/dev/null || true
    exit 2
    ;;
esac
SNAP_DIR="${BACKUP_ROOT}/upgrade-${TS}"
LOG="${SNAP_DIR}/upgrade-${TS}.log"
# The snapshot holds the live DB, API tokens, and .env — owner-only from the
# very first byte, not only at the post-snapshot chmod (which an interrupted
# run would never reach). The umask is restored right after: leaving 077
# global would give files REWRITTEN BY git checkout 0600 modes on disk (and
# carry them into build contexts). Everything inside the 0700 SNAP_DIR is
# access-gated by the directory regardless of per-file modes, and
# finalize_snapshot re-tightens with chmod -R go-rwx.
_orig_umask="$(umask)"
umask 077
mkdir -p "$SNAP_DIR"
chmod 700 "$SNAP_DIR"
umask "$_orig_umask"
# Tee everything (stdout + stderr) into the snapshot dir so a failed upgrade
# leaves a complete transcript next to the backup it can be restored from.
# Keep the original fds on 3/4: restoring them at the end lets the background
# tee flush and exit before we prune the directory it is writing into.
exec 3>&1 4>&2
exec > >(tee -a "$LOG") 2>&1

NEW_STACK_UP=0        # the upgraded stack was started (DB may be migrated)
STACK_WAS_STOPPED=0   # we took the previously-running stack down ourselves
BUILD_STARTED=0       # docker compose build ran (images may be partially retagged)
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
      docker run --rm -v "${VOL_DATA}:/data" -v "${SNAP_DIR}:/backup:ro" "$HELPER_IMAGE" \
        sh -ec 'owner="$(stat -c %u:%g /data/vedetta.db 2>/dev/null || stat -c %u:%g /data 2>/dev/null || echo 0:0)"
                rm -f /data/vedetta.db /data/vedetta.db-wal /data/vedetta.db-shm
                cp "/backup/$1" /data/vedetta.db
                chown "$owner" /data/vedetta.db' _ "$(basename "$SNAP_ARTIFACT")"
      ;;
    cold)
      docker run --rm -v "${VOL_DATA}:/data" -v "${SNAP_DIR}:/backup:ro" "$HELPER_IMAGE" \
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
  warn "Upgrade failed — recovering to ${PREV_DESC}…"

  # Through stderr (not straight into $LOG): the tee redirection captures it in
  # the log AND the operator sees the failing backend's output immediately.
  { echo "----- backend logs at failure ($(date +%H:%M:%S)) -----"
    docker compose logs --no-color --tail=200 backend 2>&1 || true
  } >&2

  # Failure BEFORE the stack was modified (e.g. the target build failed while
  # the old stack kept serving): nothing was stopped and nothing ran, so don't
  # cause downtime by tearing down a healthy stack. Just restore the tree if
  # the script had moved it.
  if [ "$NEW_STACK_UP" != "1" ] && [ "$STACK_WAS_STOPPED" != "1" ]; then
    # Repair whenever a DISTINCT known-good ref exists — the target-ref flow
    # (tree moved) and in-place mode with --from (tree never moved, but a
    # partial build may still have retagged some service images) both qualify.
    if [ "$PREV_REF" != "$fail_head" ]; then
      if git checkout --quiet "$PREV_BRANCH"; then ok "Working tree now at ${PREV_DESC}."
      else
        err "ROLLBACK INCOMPLETE: git checkout ${PREV_DESC} failed — the tree still holds"
        err "the failed version. The stack is still RUNNING the previous build; fix the"
        err "tree (git status) before any 'docker compose' build or up."
        return 1
      fi
      # A partially-successful build may have retagged SOME service images even
      # though the running containers still use the old image IDs. Rebuild at
      # the known-good ref so the compose tags point back at known-good builds —
      # otherwise a later plain `docker compose up -d` would recreate containers
      # onto the failed build. Containers are NOT restarted.
      if ! compose_build_core; then
        err "WARNING: rebuild at ${PREV_DESC} failed — compose image tags may still"
        err "point at the failed build. The running stack is unaffected, but do"
        err "NOT run 'docker compose up -d' until 'docker compose build' succeeds here."
      fi
    else
      # In-place mode with no --from: no good ref exists to repair tags with.
      warn "Note: a partial build may have retagged some service images. Do not run"
      warn "'docker compose up -d' until 'docker compose build' succeeds on this checkout."
    fi
    ok "The running stack was never touched — it stays up as-is."
    return 0
  fi

  # A failed `down` is fatal ONLY when the upgraded stack ran: containers may
  # still hold the data volume, and rewriting SQLite files underneath a live
  # process would corrupt the one copy rollback exists to protect. When nothing
  # we started is running (cold path, pre-start failure), a down failure — e.g.
  # the failed target's broken compose file — must not turn a recoverable
  # pre-start failure into a halt: no restore follows in that state.
  if ! compose_stop_core; then
    if [ "$NEW_STACK_UP" = "1" ]; then
      halt_rollback "stopping the Core services failed — containers may still have the data volume mounted; restoring over live files would corrupt them"
      return 1
    fi
    warn "stopping the Core services reported an error (nothing we started is running); continuing."
  fi

  if [ "$NEW_STACK_UP" = "1" ]; then
    # compose stop above used the CURRENT checkout's service names; a target
    # ref that renamed a service can leave an old-name container running with
    # the volume mounted. Stop by VOLUME and verify before rewriting files.
    stop_volume_users || true
    if volume_still_mounted; then
      halt_rollback "containers still have ${VOL_DATA} mounted after stopping — refusing to restore over live files"
      return 1
    fi
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
    if ! git checkout --quiet "$PREV_BRANCH"; then
      halt_rollback "git checkout ${PREV_DESC} failed — the tree still holds the failed version"
      return 1
    fi
    if ! compose_build_core; then
      halt_rollback "rebuild of the previous version failed — the compose image is still the upgraded build"
      return 1
    fi
  elif [ "$NEW_STACK_UP" = "1" ]; then
    # Rebuild-in-place with no --from: the failing version IS the current
    # checkout. Restarting it would immediately re-run the failing migration
    # against the just-restored DB, undoing the rollback.
    halt_rollback "the failed version is the current checkout — restarting it would re-run the failing migration (re-run with --from <known-good-ref> to enable automatic rollback)"
    return 1
  elif [ "$BUILD_STARTED" = "1" ]; then
    # PREV_REF == fail_head, NEW_STACK_UP=0, and a build RAN: Compose builds
    # and tags each service independently, so the failed build may ALREADY
    # have retagged some services (e.g. the backend) with the new code before
    # another service failed — `up -d` here could boot that new backend
    # against the untouched DB and run the very migrations this "failed"
    # upgrade was supposed to withhold. The stack was already down when the
    # cold path began, so halting adds no new downtime.
    halt_rollback "the failed build may have retagged some service images with the new code — starting now could migrate the untouched DB (fix the build, or re-run with --from <known-good-ref>)"
    return 1
  else
    # Cold-path failure BEFORE any build ran (snapshot/.env/checkout): nothing
    # was retagged and the DB was untouched — restart the stack as it was.
    warn "No build had started — restarting the stack as it was before the attempt…"
    compose_up_core || { halt_rollback "restarting the Core services failed"; return 1; }
    if wait_health 60; then ok "Stack is back up (pre-upgrade state)."
    else warn "Stack restarted but not healthy within 60s (the cold path implies it was already unhealthy before the attempt)."; fi
    return 0
  fi
  compose_up_core || { halt_rollback "starting the previous version's Core services failed"; return 1; }

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
  # do_rollback handles every state: stack untouched → restore tree + retag and
  # leave it serving; stack stopped pre-snapshot → restart it as it was; new
  # stack ran → restore the snapshot and relaunch the previous version.
  do_rollback
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
  Steps: checkout → build → snapshot (DB + .env + aux volumes;
  online seconds before the swap — or FIRST, cold, if the backend
  is already down) → up → verify (health, foreign_key_check,
  integrity_check). On ANY failure the pre-upgrade snapshot is
  restored and the stack returns to ${PREV_DESC}.
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

# From here on, ANY unexpected command failure routes through fail() and the
# rollback machinery (do_rollback picks the correct branch for the current
# state — including "nothing touched yet": restore the tree, keep serving).
# Interrupts too: Ctrl-C/SIGTERM while e.g. waiting out a hung migration must
# also roll back, not exit leaving the migrated DB and new images in place.
trap 'fail "unexpected error near line ${LINENO}"' ERR
trap 'fail "interrupted (SIGINT/SIGTERM)"' INT TERM

# finalize_snapshot — .env + aux volumes + permissions + arm the ERR trap.
# Runs once, right after the Core DB artifact lands (cold: step 1; warm: step 3).
finalize_snapshot() {
  ok "Core DB snapshot: $(basename "$SNAP_ARTIFACT") (${SNAP_MODE})"

  # .env sits outside the volume; capture it too (it holds deployment secrets).
  # Explicit fail: a bare `cp && ok` under set -e would die silently here (the
  # ERR trap is not registered until the snapshot section completes).
  if [ -f "${PROJECT_DIR}/.env" ]; then
    # Plain cp (no -p): preserving mode/ownership can fail on shared/network
    # filesystems, and umask 077 + the 0700 dir already keep the copy private.
    cp "${PROJECT_DIR}/.env" "${SNAP_DIR}/env-${TS}.bak" \
      || fail "could not copy .env into the snapshot directory"
    ok "Copied .env → env-${TS}.bak"
  else
    warn "No .env next to docker-compose.yml — skipping .env backup."
  fi

  # Auxiliary volumes (cold tarball; best-effort — the Core DB is what matters).
  if [ "$SKIP_AUX" != "1" ]; then
    local key vol out
    for key in telemetry-state threat-network-data; do
      vol="$(resolve_volume "$key" || true)"
      if [ -n "$vol" ] && volume_exists "$vol"; then
        out="${key}-${TS}.tar.gz"
        if docker run --rm -v "${vol}:/data:ro" -v "${SNAP_DIR}:/backup" "$HELPER_IMAGE" \
             sh -ec 'tar czf "/backup/$1" -C /data . && chown "$2" "/backup/$1"' \
             _ "${out}" "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}"; then
          ok "Snapshotted ${key} → ${out}"
        else
          warn "Could not snapshot ${key} (continuing; auxiliary volume)."
        fi
      else
        warn "No ${key} volume present — skipping."
      fi
    done
  fi

  chmod -R go-rwx "$SNAP_DIR" 2>/dev/null || true   # snapshots hold DB + tokens + .env
  # (The ERR trap is registered right after the confirmation prompt, so the
  # checkout/build phases are covered too — not only the post-snapshot steps.)
}

# ─── 1. Snapshot strategy ─────────────────────────────────────────────────────
# Cold (backend down/crash-looping): stop the stack and snapshot NOW — the data
# cannot change and the online path has nothing to exec into.
# Warm (backend healthy): keep the stack SERVING through checkout+build and take
# the online snapshot in step 3, seconds before the container swap — so a
# rollback discards at most the swap window's writes, not the whole build's.
step "Choosing snapshot strategy…"
WARM=0
if backend_running && wait_health 5; then
  WARM=1
  ok "Backend is healthy — online snapshot will be taken right before the swap."
else
  warn "Backend is not healthy — stopping the stack for a cold volume snapshot."
  STACK_WAS_STOPPED=1
  # A failed down means something may still be writing to the volume; tarring
  # it anyway could produce a corrupt backup the rollback would then trust.
  compose_stop_core \
    || fail "stopping the Core services failed — refusing to snapshot a volume that may still be written to"
  # Also stop any off-list container mounting the volume (renamed/removed
  # services, one-offs) and prove the volume is quiet before tarring it.
  stop_volume_users || true
  if volume_still_mounted; then
    fail "containers still have ${VOL_DATA} mounted — refusing to snapshot a volume that may still be written to"
  fi
  SNAP_ARTIFACT="${SNAP_DIR}/vedetta-data-${TS}.tar.gz"
  # chown the tarball to the invoking host user — the helper container runs as
  # root, and a root-owned backup would need sudo to manage or prune later.
  docker run --rm -v "${VOL_DATA}:/data:ro" -v "${SNAP_DIR}:/backup" "$HELPER_IMAGE" \
    sh -ec 'tar czf "/backup/$1" -C /data . && chown "$2" "/backup/$1"' \
    _ "$(basename "$SNAP_ARTIFACT")" "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" \
    || fail "cold volume snapshot failed"
  SNAP_MODE="cold"
  finalize_snapshot
fi

# ─── 2. Check out target + build ──────────────────────────────────────────────
if [ -n "$TARGET_REF" ]; then
  step "Checking out ${TARGET_REF}…"
  git checkout --quiet "$TARGET_REF" || fail "git checkout ${TARGET_REF} failed"
else
  step "No target ref given — rebuilding the current checkout in place."
fi

step "Building Core images${NO_CACHE:+ (--no-cache)}…"
BUILD_STARTED=1
compose_build_core || fail "docker compose build failed"

# ─── 3. Warm snapshot (immediately before the swap) ──────────────────────────
if [ "$WARM" = "1" ]; then
  step "Snapshotting (online, no downtime) before the swap…"
  SNAP_ARTIFACT="${SNAP_DIR}/vedetta-db-pre-${TS}.db"
  # .timeout: ride out transient locks from the still-serving backend's writes
  # (same silent dot-command the verification PRAGMAs use).
  # On failure, remove the (possibly partial) in-volume copy before failing —
  # e.g. a disk-full .backup would otherwise leave the live volume full while
  # the untouched old stack keeps serving.
  docker compose exec -T backend sqlite3 -batch -cmd '.timeout 5000' /data/vedetta.db \
    ".backup '/data/pre-${TS}.db'" \
    || { remove_temp_backup || true
         fail "online .backup failed"; }
  # Plain `docker cp` (not `docker compose cp`, which needs Compose >= 2.20),
  # and clean the in-container temp file up on BOTH exits so a failed copy
  # doesn't leave a full DB copy eating the data volume. Guard the container id:
  # the backend could crash between the health probe and this copy, and an
  # empty id would make `docker cp` fail with a confusing usage error.
  backend_cid="$(docker compose ps -q backend | head -n1)"
  if [ -z "$backend_cid" ]; then
    remove_temp_backup || true   # don't leave a full DB copy in the live volume
    fail "backend container disappeared before the snapshot could be copied out"
  fi
  if ! docker cp "${backend_cid}:/data/pre-${TS}.db" "$SNAP_ARTIFACT"; then
    remove_temp_backup || true
    fail "copying the snapshot out of the container failed"
  fi
  remove_temp_backup \
    || warn "could not remove the temp snapshot — free the space manually: /data/pre-${TS}.db in ${VOL_DATA}"
  SNAP_MODE="online"
  finalize_snapshot

  # The swap below recreates the Core containers anyway, so explicitly stopping
  # ALL volume users first costs no extra downtime — and it closes the rename
  # gap: `up` with the TARGET ref's service names would leave an old-name
  # container running as a second writer while the new service migrates the DB.
  STACK_WAS_STOPPED=1   # from here, rollback must not treat the stack as untouched
  stop_volume_users || true
  if volume_still_mounted; then
    fail "containers still have ${VOL_DATA} mounted after stopping — refusing to start the upgraded stack alongside a live writer"
  fi
fi

# ─── 4. Bring the stack up ────────────────────────────────────────────────────
step "Starting the upgraded stack…"
NEW_STACK_UP=1
compose_up_core || fail "starting the upgraded Core services failed"

# ─── 4. Verify ────────────────────────────────────────────────────────────────
step "Waiting up to ${HEALTH_TIMEOUT}s for the backend to become healthy…"
wait_health "$HEALTH_TIMEOUT" || fail "backend did not become healthy within ${HEALTH_TIMEOUT}s (migration crash-loop?)"
ok "Backend healthy."

step "Verifying database integrity…"
# NB: set the busy timeout with the SILENT `.timeout` dot-command, not an inline
# `PRAGMA busy_timeout=…;` — that PRAGMA echoes its value as an output row, which
# would look like a foreign_key_check violation and roll back every upgrade.
# (No stderr redirect: the global tee already logs it, and the operator should
# see sqlite/exec errors on the console immediately.)
fk="$(docker compose exec -T backend sqlite3 -batch -cmd '.timeout 5000' /data/vedetta.db \
      'PRAGMA foreign_key_check;')" \
  || fail "could not run PRAGMA foreign_key_check on the upgraded DB"
if [ -n "$fk" ]; then
  err "foreign_key_check reported violations:"; printf '%s\n' "$fk" | sed 's/^/    /' >&2
  fail "post-upgrade foreign_key_check found violations"
fi
ok "foreign_key_check: clean (0 rows)."

integ="$(docker compose exec -T backend sqlite3 -batch -cmd '.timeout 5000' /data/vedetta.db \
        'PRAGMA integrity_check;')" \
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
  # Detach from the log's tee first so it flushes, closes the file inside
  # SNAP_DIR, and exits — otherwise the rm can hit file-busy on some mounts.
  exec 1>&3 2>&4 3>&- 4>&-
  sleep 1   # give the background tee a moment to drain and release the log
  if rm -rf "$SNAP_DIR"; then echo "  ✓ Pruned snapshot (--prune-on-success)."
  else warn "Could not prune the snapshot directory — remove it manually: ${SNAP_DIR}"; fi
else
  ok "Pre-upgrade snapshot kept at: ${SNAP_DIR}"
  ok "It contains your DB, .env, and API tokens — treat it as sensitive and keep"
  ok "it until you have confirmed the new version in daily use."
  exec 1>&3 2>&4 3>&- 4>&-
fi
