#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
DEPLOY_SCRIPT="$ROOT/scripts/deploy.sh"
RANGE_SCRIPT="$ROOT/scripts/select-sanitation-range.sh"
UPDATE_SCRIPT="$ROOT/scripts/update-all.sh"
REAL_GIT="$(command -v git)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

tests=0
failures=0

ok() {
    tests=$((tests + 1))
    local description="${!#}"
    local command_count=$(($# - 1))
    local -a command=("${@:1:$command_count}")
    if "${command[@]}"; then
        printf 'ok %d - %s\n' "$tests" "$description"
    else
        printf 'not ok %d - %s\n' "$tests" "$description"
        failures=$((failures + 1))
    fi
}

is() {
    tests=$((tests + 1))
    if [[ "$1" == "$2" ]]; then
        printf 'ok %d - %s\n' "$tests" "$3"
    else
        printf 'not ok %d - %s\n' "$tests" "$3"
        printf '  expected: %q\n  actual:   %q\n' "$2" "$1"
        failures=$((failures + 1))
    fi
}

not_grep() {
    ! grep -Fq -- "$1" "$2"
}

git_identity() {
    git -C "$1" config user.name "Vedetta deploy test"
    git -C "$1" config user.email "deploy-test@example.invalid"
}

commit_file() {
    local repo="$1" path="$2" contents="$3" message="$4"
    mkdir -p "$(dirname -- "$repo/$path")"
    printf '%s\n' "$contents" >"$repo/$path"
    git -C "$repo" add -- "$path"
    git -C "$repo" commit -qm "$message"
}

# ---- GitHub range selection -------------------------------------------------

RANGE_REPO="$TMP/range"
RANGE_REMOTE="$TMP/range.git"
git init -q --bare --initial-branch=main "$RANGE_REMOTE"
git init -q -b main "$RANGE_REPO"
git_identity "$RANGE_REPO"
commit_file "$RANGE_REPO" README.md base A
A="$(git -C "$RANGE_REPO" rev-parse HEAD)"
git -C "$RANGE_REPO" remote add origin "$RANGE_REMOTE"
git -C "$RANGE_REPO" push -qu -u origin main
git -C "$RANGE_REPO" switch -qc feature
commit_file "$RANGE_REPO" feature.txt one B
B="$(git -C "$RANGE_REPO" rev-parse HEAD)"
commit_file "$RANGE_REPO" feature.txt two C
C="$(git -C "$RANGE_REPO" rev-parse HEAD)"
empty_tree="$(git -C "$RANGE_REPO" mktree </dev/null)"
UNRELATED="$(printf 'unrelated\n' | git -C "$RANGE_REPO" commit-tree "$empty_tree")"

select_range() {
    local event="$1" ref_type="$2" ref_name="$3" before="$4" head="$5" base="${6:-}"
    local output="$TMP/range-output"
    : >"$output"
    (
        cd "$RANGE_REPO"
        GITHUB_OUTPUT="$output" \
        SANITATION_EVENT_NAME="$event" \
        SANITATION_REF_TYPE="$ref_type" \
        SANITATION_REF_NAME="$ref_name" \
        SANITATION_BEFORE_SHA="$before" \
        SANITATION_HEAD_SHA="$head" \
        SANITATION_BASE_SHA="$base" \
        SANITATION_DEFAULT_BRANCH=main \
        bash "$RANGE_SCRIPT"
    )
    SELECT_SCAN="$(sed -n 's/^should_scan=//p' "$output")"
    SELECT_RANGE="$(sed -n 's/^range=//p' "$output")"
}

select_range push branch feature "$A" "$B"
is "$SELECT_SCAN|$SELECT_RANGE" "true|$A..$B" "normal branch push selects before..after"

select_range push branch feature "$C" "$B"
is "$SELECT_RANGE" "$C..$B" "force-push preserves the exact before..after set"

select_range push branch feature "0000000000000000000000000000000000000000" "$B"
is "$SELECT_RANGE" "$A..$B" "new branch anchors at default-branch merge base"

select_range push branch feature "0000000000000000000000000000000000000000" "$A"
is "$SELECT_RANGE" "$A^!" "new branch at an existing main commit scans only its exact tree"

select_range push tag v-test "0000000000000000000000000000000000000000" "$A"
is "$SELECT_RANGE" "$A^!" "new tag at an existing main commit avoids full-history rescan"

select_range push tag v-unrelated "0000000000000000000000000000000000000000" "$UNRELATED"
is "$SELECT_RANGE" "$UNRELATED" "unrelated tag scans complete reachable history"

select_range push branch main "0000000000000000000000000000000000000000" "$A"
is "$SELECT_RANGE" "$A" "recreated default branch scans complete reachable history"

select_range push branch feature "0000000000000000000000000000000000000000" "0000000000000000000000000000000000000000"
is "$SELECT_SCAN|$SELECT_RANGE" "false|" "deleted ref publishes no tree"

if (
    cd "$RANGE_REPO"
    SANITATION_EVENT_NAME=push SANITATION_REF_TYPE=branch SANITATION_REF_NAME=feature \
    SANITATION_BEFORE_SHA="$A" SANITATION_HEAD_SHA="" SANITATION_DEFAULT_BRANCH=main \
    bash "$RANGE_SCRIPT" >/dev/null 2>&1
); then
    EMPTY_HEAD_RC=0
else
    EMPTY_HEAD_RC=$?
fi
ok test "$EMPTY_HEAD_RC" -ne 0 "missing pushed head fails closed instead of impersonating deletion"

if (
    cd "$RANGE_REPO"
    SANITATION_EVENT_NAME=push SANITATION_REF_TYPE="" SANITATION_REF_NAME=feature \
    SANITATION_BEFORE_SHA="$A" SANITATION_HEAD_SHA="$B" SANITATION_DEFAULT_BRANCH=main \
    bash "$RANGE_SCRIPT" >/dev/null 2>&1
); then
    EMPTY_REF_TYPE_RC=0
else
    EMPTY_REF_TYPE_RC=$?
fi
ok test "$EMPTY_REF_TYPE_RC" -ne 0 "missing push ref type fails closed"

select_range push branch feature "ffffffffffffffffffffffffffffffffffffffff" "$B"
is "$SELECT_RANGE" "$A..$B" "missing force-push predecessor falls back to trusted merge base"

select_range pull_request branch feature "" "$B" "$A"
is "$SELECT_RANGE" "$A..$B" "pull request selects exact base..head"

ALL_REF_WORKFLOW="$ROOT/.github/workflows/repository-sanitation.yml"
ok grep -Fq 'branches: ["**"]' "$ALL_REF_WORKFLOW" "best-effort detector declares every branch push trigger"
ok grep -Fq 'tags: ["**"]' "$ALL_REF_WORKFLOW" "best-effort detector declares every tag push trigger"
ok grep -Fq 'old ref without this workflow' "$ALL_REF_WORKFLOW" "workflow documents GitHub's ref-owned detection limit"
ok not_grep 'concurrency:' "$ALL_REF_WORKFLOW" "every emitted workflow run remains independently runnable"
ok not_grep 'cancel-in-progress:' "$ALL_REF_WORKFLOW" "later pushes cannot cancel an earlier publication scan"

# ---- Deployment fixtures ----------------------------------------------------

setup_case() {
    local name="$1" remote_name="${2:-origin}"
    CASE_DIR="$TMP/$name"
    BARE="$CASE_DIR/repository.git"
    SEED="$CASE_DIR/seed"
    LOCAL="$CASE_DIR/local"
    TARGET="$CASE_DIR/deployment host"
    RACER="$CASE_DIR/racer"
    BIN="$CASE_DIR/bin"
    SCAN_LOG="$CASE_DIR/scan.log"
    SSH_LOG="$CASE_DIR/ssh.log"
    UPDATE_MARKER="$CASE_DIR/update.marker"
    UNREVIEWED_MARKER="$CASE_DIR/unreviewed.marker"
    OUTPUT="$CASE_DIR/deploy.out"
    mkdir -p "$CASE_DIR" "$BIN"
    git init -q --bare --initial-branch=main "$BARE"
    git init -q -b main "$SEED"
    git_identity "$SEED"
    mkdir -p "$SEED/scripts/lib" "$SEED/backend" "$SEED/frontend" \
        "$SEED/collector" "$SEED/telemetry" "$SEED/sensor" \
        "$SEED/siem/migrations"
    printf '%s\n' base >"$SEED/README.md"
    for tracked_root in backend frontend collector telemetry sensor; do
        printf '%s\n' tracked >"$SEED/$tracked_root/.tracked"
    done
    printf '%s\n' tracked >"$SEED/siem/migrations/.tracked"
    printf '%s\n' \
        '*secret*' \
        'vendor/' \
        '/backend/vedetta' \
        '/sensor/vedetta-sensor' \
        '/telemetry/telemetry' \
        'docker-compose.override.yml' \
        'frontend/node_modules/' \
        'frontend/dist/' \
        'frontend/.env*' >"$SEED/.gitignore"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'printf "%s\n" "$*" >>"${VEDETTA_TEST_SCAN_LOG:?}"' \
        'marker="LAB_""LEAK"' \
        'if git grep --cached -q -- "$marker" -- 2>/dev/null; then exit 86; fi' \
        'while (($#)); do' \
        '  if [[ "$1" == "--history-range" ]]; then' \
        '    range="$2"; shift 2' \
        '    while IFS= read -r revision; do' \
        '      if git grep -q -- "$marker" "$revision" -- 2>/dev/null; then exit 86; fi' \
        '    done < <(git rev-list "$range")' \
        '  else shift; fi' \
        'done' >"$SEED/scripts/check-repo-sanitization.sh"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'if [[ -n "${VEDETTA_PINNED_PORT_CONFIG_FD:-}" ]]; then' \
        '  source "/dev/fd/$VEDETTA_PINNED_PORT_CONFIG_FD"' \
        'else' \
        '  source "$(dirname "$0")/lib/port-config.sh"' \
        'fi' \
        'actual="$(git rev-parse HEAD)"' \
        'if [[ "${VEDETTA_EXPECTED_HEAD:?}" != "$actual" ]]; then' \
        '  echo "Pinned update expected $VEDETTA_EXPECTED_HEAD but checkout is $actual." >&2' \
        '  exit 2' \
        'fi' \
        'if [[ -n "${VEDETTA_TEST_REQUIRED_INPUT:-}" ]]; then' \
        '  IFS= read -r answer' \
        '  test "$answer" = "$VEDETTA_TEST_REQUIRED_INPUT"' \
        'fi' \
        'printf "%s\n" "$actual" >"${VEDETTA_TEST_UPDATE_MARKER:?}"' >"$SEED/scripts/update-all.sh"
    printf '%s\n' '# reviewed port configuration fixture' >"$SEED/scripts/lib/port-config.sh"
    chmod +x "$SEED/scripts/check-repo-sanitization.sh" "$SEED/scripts/update-all.sh"
    git -C "$SEED" add .
    git -C "$SEED" commit -qm base
    A_CASE="$(git -C "$SEED" rev-parse HEAD)"
    git -C "$SEED" remote add origin "$BARE"
    git -C "$SEED" push -qu -u origin main

    git clone -q "$BARE" "$LOCAL"
    git clone -q "$BARE" "$TARGET"
    git_identity "$LOCAL"
    git_identity "$TARGET"
    if [[ "$remote_name" != "origin" ]]; then
        git -C "$LOCAL" remote rename origin "$remote_name"
    fi
    REMOTE_NAME="$remote_name"

    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'host="$1"; shift' \
        'printf "%s\n" "$host" >>"${VEDETTA_TEST_SSH_LOG:?}"' \
        'call_count="$(wc -l <"$VEDETTA_TEST_SSH_LOG" | tr -d " ")"' \
        'if [[ "$call_count" == "1" && -n "${VEDETTA_TEST_POST_PUSH_RACE:-}" ]]; then' \
        '  bash "$VEDETTA_TEST_POST_PUSH_RACE"' \
        'fi' \
        'if [[ "$call_count" == "2" && -n "${VEDETTA_TEST_PRE_UPDATE_RACE:-}" ]]; then' \
        '  bash "$VEDETTA_TEST_PRE_UPDATE_RACE"' \
        'fi' \
        '# OpenSSH does not forward these local Git trust variables by default.' \
        'unset GIT_NO_REPLACE_OBJECTS GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR || true' \
        'if [[ -n "${VEDETTA_TEST_REMOTE_GIT_EXEC_PATH:-}" ]]; then export GIT_EXEC_PATH="$VEDETTA_TEST_REMOTE_GIT_EXEC_PATH"; fi' \
        'if [[ -n "${VEDETTA_TEST_REMOTE_ALLOW_PROTOCOL:-}" ]]; then export GIT_ALLOW_PROTOCOL="$VEDETTA_TEST_REMOTE_ALLOW_PROTOCOL"; fi' \
        'exec bash -c "$1"' >"$BIN/ssh"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'if [[ -n "${VEDETTA_TEST_FETCH_RACE:-}" && "$1" == "fetch" && ! -e "${VEDETTA_TEST_FETCH_RACE}.done" ]]; then' \
        '  : >"${VEDETTA_TEST_FETCH_RACE}.done"' \
        '  bash "$VEDETTA_TEST_FETCH_RACE"' \
        'fi' \
        'exec "${VEDETTA_TEST_REAL_GIT:?}" "$@"' >"$BIN/git"
    chmod +x "$BIN/ssh" "$BIN/git"
    : >"$SCAN_LOG"
    : >"$SSH_LOG"
    unset VEDETTA_TEST_POST_PUSH_RACE VEDETTA_TEST_FETCH_RACE VEDETTA_TEST_RACER \
        VEDETTA_TEST_LOCAL VEDETTA_TEST_DEPLOY_STDIN VEDETTA_TEST_REQUIRED_INPUT \
        VEDETTA_TEST_PRE_UPDATE_RACE VEDETTA_TEST_TARGET \
        VEDETTA_TEST_REMOTE_GIT_EXEC_PATH VEDETTA_TEST_REMOTE_ALLOW_PROTOCOL || true
}

invoke_deploy() {
    (
        cd "$LOCAL"
        VEDETTA_DEPLOY_HOST=placeholder
        export VEDETTA_DEPLOY_HOST
        PATH="$BIN:$PATH" \
        VEDETTA_REMOTE_DIR="$TARGET" \
        VEDETTA_TEST_SCAN_LOG="$SCAN_LOG" \
        VEDETTA_TEST_UPDATE_MARKER="$UPDATE_MARKER" \
        VEDETTA_TEST_UNREVIEWED_MARKER="$UNREVIEWED_MARKER" \
        VEDETTA_TEST_SSH_LOG="$SSH_LOG" \
        VEDETTA_TEST_POST_PUSH_RACE="${VEDETTA_TEST_POST_PUSH_RACE:-}" \
        VEDETTA_TEST_PRE_UPDATE_RACE="${VEDETTA_TEST_PRE_UPDATE_RACE:-}" \
        VEDETTA_TEST_FETCH_RACE="${VEDETTA_TEST_FETCH_RACE:-}" \
        VEDETTA_TEST_RACER="${VEDETTA_TEST_RACER:-}" \
        VEDETTA_TEST_LOCAL="$LOCAL" \
        VEDETTA_TEST_TARGET="$TARGET" \
        VEDETTA_TEST_REQUIRED_INPUT="${VEDETTA_TEST_REQUIRED_INPUT:-}" \
        VEDETTA_TEST_REMOTE_GIT_EXEC_PATH="${VEDETTA_TEST_REMOTE_GIT_EXEC_PATH:-}" \
        VEDETTA_TEST_REMOTE_ALLOW_PROTOCOL="${VEDETTA_TEST_REMOTE_ALLOW_PROTOCOL:-}" \
        VEDETTA_TEST_REAL_GIT="$REAL_GIT" \
        bash "$DEPLOY_SCRIPT"
    )
}

run_deploy() {
    set +e
    if [[ -n "${VEDETTA_TEST_DEPLOY_STDIN:-}" ]]; then
        invoke_deploy <<<"$VEDETTA_TEST_DEPLOY_STDIN" >"$OUTPUT" 2>&1
    else
        invoke_deploy >"$OUTPUT" 2>&1
    fi
    DEPLOY_RC=$?
    set -e
}

setup_case normal
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
ssh() {
    printf exported-ssh >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"
    return 98
}
export -f ssh
run_deploy
unset -f ssh
is "$DEPLOY_RC" "0" "normal exact-SHA deployment succeeds"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$B_CASE" "normal deployment publishes reviewed SHA"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "normal deployment runs update at reviewed SHA"
ok test ! -e "$UNREVIEWED_MARKER" "both deployment-host sessions ignore an exported ssh function"
is "$(wc -l <"$SSH_LOG" | tr -d ' ')" "2" "both deployment-host sessions use the resolved external ssh"
ok grep -q "$B_CASE^!" "$SCAN_LOG" "normal deployment scans exact committed tree"
ok grep -q "$A_CASE..$B_CASE" "$SCAN_LOG" "normal deployment scans unpublished history"

setup_case interactive-update-stdin
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
VEDETTA_TEST_REQUIRED_INPUT=continue
VEDETTA_TEST_DEPLOY_STDIN=continue
run_deploy
is "$DEPLOY_RC" "0" "remote updater retains operator stdin after checkout heredoc"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "interactive updater reaches the reviewed SHA"
is "$(wc -l <"$SSH_LOG" | tr -d ' ')" "2" "checkout verification and interactive update use separate SSH sessions"

setup_case between-session-head-race
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
PRE_UPDATE_RACE="$CASE_DIR/pre-update-race.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" "#!/usr/bin/env bash" "printf unreviewed >\"\${VEDETTA_TEST_UNREVIEWED_MARKER:?}\"" >"$VEDETTA_TEST_TARGET/scripts/update-all.sh"' \
    'git -C "$VEDETTA_TEST_TARGET" add scripts/update-all.sh' \
    'git -C "$VEDETTA_TEST_TARGET" commit -qm between-session-race' >"$PRE_UPDATE_RACE"
chmod +x "$PRE_UPDATE_RACE"
VEDETTA_TEST_PRE_UPDATE_RACE="$PRE_UPDATE_RACE"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "checkout movement between SSH sessions fails closed"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$B_CASE" "between-session race does not alter the published reviewed SHA"
ok test ! -e "$UPDATE_MARKER" "between-session race performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "between-session race never executes the replacement updater"
ok grep -Fq 'Remote checkout moved before reviewed updater launch' "$OUTPUT" "trusted launcher reports the exact-head mismatch"

setup_case dirty-between-session-updater
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
PRE_UPDATE_RACE="$CASE_DIR/pre-update-race.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" "#!/usr/bin/env bash" "printf unreviewed >\"\${VEDETTA_TEST_UNREVIEWED_MARKER:?}\"" >"$VEDETTA_TEST_TARGET/scripts/update-all.sh"' >"$PRE_UPDATE_RACE"
chmod +x "$PRE_UPDATE_RACE"
VEDETTA_TEST_PRE_UPDATE_RACE="$PRE_UPDATE_RACE"
run_deploy
is "$DEPLOY_RC" "0" "reviewed updater blob runs when only the worktree copy is replaced"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "reviewed updater blob, not the dirty worktree path, performs the update"
ok test ! -e "$UNREVIEWED_MARKER" "dirty replacement updater is never executed"

setup_case dirty-between-session-port-config
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
PRE_UPDATE_RACE="$CASE_DIR/pre-update-race.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" "printf unreviewed >\"\${VEDETTA_TEST_UNREVIEWED_MARKER:?}\"" >"$VEDETTA_TEST_TARGET/scripts/lib/port-config.sh"' >"$PRE_UPDATE_RACE"
chmod +x "$PRE_UPDATE_RACE"
VEDETTA_TEST_PRE_UPDATE_RACE="$PRE_UPDATE_RACE"
run_deploy
is "$DEPLOY_RC" "0" "reviewed port configuration blob runs when the worktree helper is replaced"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "pinned helper preserves the reviewed updater path"
ok test ! -e "$UNREVIEWED_MARKER" "dirty replacement port helper is never sourced"

setup_case remote-replace-object
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
printf '%s\n' malicious >"$TARGET/README.md"
git -C "$TARGET" add README.md
MALICIOUS_TREE="$(git -C "$TARGET" write-tree)"
MALICIOUS_COMMIT="$(printf '%s\n' malicious-replacement | git -C "$TARGET" commit-tree "$MALICIOUS_TREE" -p "$A_CASE")"
git -C "$TARGET" reset -q --hard "$A_CASE"
git -C "$TARGET" update-ref "refs/replace/$B_CASE" "$MALICIOUS_COMMIT"
run_deploy
is "$DEPLOY_RC" "0" "replacement objects cannot alter the reviewed deployment tree"
is "$(cat "$TARGET/README.md")" "base" "remote checkout ignores a malicious replacement tree"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "pinned updater ignores replacement objects too"

setup_case remote-git-executors
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf hook >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' >"$TARGET/.git/hooks/post-merge"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf hook >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' >"$TARGET/.git/hooks/reference-transaction"
FSMONITOR="$CASE_DIR/fsmonitor.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf fsmonitor >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'printf "\\n"' >"$FSMONITOR"
chmod +x "$TARGET/.git/hooks/post-merge" "$TARGET/.git/hooks/reference-transaction" "$FSMONITOR"
git -C "$TARGET" config core.fsmonitor "$FSMONITOR"
run_deploy
is "$DEPLOY_RC" "0" "repository-local Git executors cannot alter reviewed deployment"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "deployment succeeds with hooks and fsmonitor neutralized"
ok test ! -e "$UNREVIEWED_MARKER" "remote hooks and fsmonitor are never executed"

setup_case remote-ambient-git-executors
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
MALICIOUS_GIT_EXEC_PATH="$CASE_DIR/git-exec"
mkdir -p "$MALICIOUS_GIT_EXEC_PATH"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf git-exec-path >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$MALICIOUS_GIT_EXEC_PATH/git-upload-pack"
chmod +x "$MALICIOUS_GIT_EXEC_PATH/git-upload-pack"
VEDETTA_TEST_REMOTE_GIT_EXEC_PATH="$MALICIOUS_GIT_EXEC_PATH"
VEDETTA_TEST_REMOTE_ALLOW_PROTOCOL=ext
run_deploy
is "$DEPLOY_RC" "0" "ambient Git executor and protocol variables cannot alter deployment"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "deployment uses the reviewed repository despite hostile ambient Git variables"
ok test ! -e "$UNREVIEWED_MARKER" "ambient GIT_EXEC_PATH program is never executed"

setup_case remote-helper-url-scheme
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf remote-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-foo"
chmod +x "$BIN/git-remote-foo"
git -C "$TARGET" remote set-url origin 'foo://example.invalid/repository'
VEDETTA_TEST_REMOTE_ALLOW_PROTOCOL=foo
run_deploy
ok test "$DEPLOY_RC" -ne 0 "an unknown URI scheme fails closed before Git fetch"
ok test ! -e "$UPDATE_MARKER" "unknown URI scheme performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "unknown URI scheme never executes its remote helper"
ok grep -Fq 'explicit supported URL or absolute path' "$OUTPUT" "unknown URI scheme has an explicit diagnostic"

setup_case remote-helper-double-colon
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf remote-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-foo"
chmod +x "$BIN/git-remote-foo"
git -C "$TARGET" remote set-url origin 'foo::repository'
VEDETTA_TEST_REMOTE_ALLOW_PROTOCOL=foo
run_deploy
ok test "$DEPLOY_RC" -ne 0 "transport double-colon syntax fails closed before Git fetch"
ok test ! -e "$UPDATE_MARKER" "transport double-colon syntax performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "transport double-colon syntax never executes its remote helper"
ok grep -Fq 'explicit supported URL or absolute path' "$OUTPUT" "transport double-colon syntax has an explicit diagnostic"

setup_case remote-custom-protocol-config
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf remote-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-foo"
chmod +x "$BIN/git-remote-foo"
git -C "$TARGET" remote set-url origin 'foo://example.invalid/repository'
git -C "$TARGET" config --local protocol.foo.allow always
run_deploy
ok test "$DEPLOY_RC" -ne 0 "repository-local custom protocol permission fails closed"
ok test ! -e "$UPDATE_MARKER" "custom protocol permission performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "custom protocol permission is rejected before its helper runs"
ok grep -Fq 'unsupported external executor or object source' "$OUTPUT" "custom protocol permission has an explicit diagnostic"

setup_case remote-command-bearing-config
commit_file "$LOCAL" safe.txt safe B
EXECUTOR="$CASE_DIR/executor.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf git-config >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$EXECUTOR"
chmod +x "$EXECUTOR"
git -C "$TARGET" config --local core.askPass "$EXECUTOR"
git -C "$TARGET" config --local core.gitProxy "$EXECUTOR"
git -C "$TARGET" config --local core.alternateRefsCommand "$EXECUTOR"
git -C "$TARGET" config --local gc.recentObjectsHook "$EXECUTOR"
git -C "$TARGET" config --local gpg.program "$EXECUTOR"
git -C "$TARGET" config --local merge.verifySignatures true
git -C "$TARGET" config --local branch.main.mergeOptions --verify-signatures
git -C "$TARGET" config --local fetch.bundleURI "file://$BARE"
git -C "$TARGET" config --local remote.origin.promisor true
git -C "$TARGET" config --local remote.origin.uploadpack "$EXECUTOR"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "command-bearing and alternate-object Git configuration fails closed"
ok test ! -e "$UPDATE_MARKER" "unsafe Git configuration performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "unsafe Git configuration is rejected before any configured program runs"
ok grep -Fq 'unsupported external executor or object source' "$OUTPUT" "unsafe Git configuration has an explicit diagnostic"

setup_case remote-object-alternates
commit_file "$LOCAL" safe.txt safe B
EXECUTOR="$CASE_DIR/alternate-refs.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf alternate-refs >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$EXECUTOR"
chmod +x "$EXECUTOR"
printf '%s\n' "$BARE/objects" >"$TARGET/.git/objects/info/alternates"
git -C "$TARGET" config --local core.alternateRefsCommand "$EXECUTOR"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "alternate object storage fails closed before deployment"
ok test ! -e "$UPDATE_MARKER" "alternate object storage performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "alternate-refs command is never executed"
ok grep -Fq 'redirects the reviewed repository or object graph' "$OUTPUT" "alternate object storage has an explicit diagnostic"

setup_case remote-common-directory
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' . >"$TARGET/.git/commondir"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "an explicit Git common-directory redirect fails closed"
ok test ! -e "$UPDATE_MARKER" "common-directory redirect performs no updater side effect"
ok grep -Fq 'redirects the reviewed repository or object graph' "$OUTPUT" "common-directory redirect has an explicit diagnostic"

setup_case remote-url-alias
commit_file "$LOCAL" safe.txt safe B
git -C "$TARGET" remote add evil "$BARE"
git -C "$TARGET" remote set-url origin evil
run_deploy
ok test "$DEPLOY_RC" -ne 0 "an upstream URL that names another remote fails closed"
ok test ! -e "$UPDATE_MARKER" "remote-name URL ambiguity performs no updater side effect"
ok grep -Fq 'explicit supported URL or absolute path' "$OUTPUT" "remote-name URL ambiguity has an explicit diagnostic"

setup_case between-session-promisor-config
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
EXECUTOR="$CASE_DIR/upload-pack.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf promisor >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$EXECUTOR"
chmod +x "$EXECUTOR"
PRE_UPDATE_RACE="$CASE_DIR/pre-update-race.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    "\"$REAL_GIT\" -C \"$TARGET\" config --local remote.origin.promisor true" \
    "\"$REAL_GIT\" -C \"$TARGET\" config --local remote.origin.uploadpack \"$EXECUTOR\"" >"$PRE_UPDATE_RACE"
chmod +x "$PRE_UPDATE_RACE"
VEDETTA_TEST_PRE_UPDATE_RACE="$PRE_UPDATE_RACE"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "between-session promisor metadata is rejected by the immutable launcher"
is "$(git -C "$TARGET" rev-parse HEAD)" "$B_CASE" "promisor race occurs only after the reviewed checkout reaches its exact head"
ok test ! -e "$UPDATE_MARKER" "promisor race performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "promisor upload-pack program is never executed"
ok grep -Fq 'unsupported external executor or object source' "$OUTPUT" "promisor race has an explicit diagnostic"

setup_case between-session-custom-protocol
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf remote-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-foo"
chmod +x "$BIN/git-remote-foo"
PRE_UPDATE_RACE="$CASE_DIR/pre-update-race.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    "\"$REAL_GIT\" -C \"$TARGET\" remote set-url origin 'foo::repository'" \
    "\"$REAL_GIT\" -C \"$TARGET\" config --local protocol.foo.allow always" >"$PRE_UPDATE_RACE"
chmod +x "$PRE_UPDATE_RACE"
VEDETTA_TEST_PRE_UPDATE_RACE="$PRE_UPDATE_RACE"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "between-session custom protocol metadata is rejected by the immutable launcher"
is "$(git -C "$TARGET" rev-parse HEAD)" "$B_CASE" "custom protocol race occurs only after the reviewed checkout reaches its exact head"
ok test ! -e "$UPDATE_MARKER" "custom protocol race performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "between-session custom protocol helper is never executed"
ok grep -Fq 'unsupported external executor or object source' "$OUTPUT" "custom protocol race has an explicit diagnostic"

setup_case remote-worktree-redirect
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
ALTERNATE_WORKTREE="$CASE_DIR/alternate-worktree"
mkdir -p "$ALTERNATE_WORKTREE"
git -C "$TARGET" checkout-index -a --prefix="$ALTERNATE_WORKTREE/"
printf '%s\n' malicious >"$TARGET/README.md"
git -C "$TARGET" config core.worktree "$ALTERNATE_WORKTREE"
ok git -C "$TARGET" diff --quiet -- "core.worktree redirect hides a dirty deployment directory from ordinary Git"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "canonical worktree binding rejects redirected Git metadata"
ok test ! -e "$UPDATE_MARKER" "redirected worktree performs no updater side effect"
ok grep -Fq 'Remote tracked file bytes differ from the reviewed index' "$OUTPUT" "redirected worktree failure is explicit"

setup_case remote-info-attributes-filter
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
printf '%s\n' malicious >"$TARGET/README.md"
printf '%s\n' 'README.md filter=hide-change' >"$TARGET/.git/info/attributes"
git -C "$TARGET" config filter.hide-change.clean 'sed s/malicious/base/'
ok git -C "$TARGET" diff --quiet -- "info attributes and a clean filter hide malicious tracked bytes from ordinary Git"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "unreviewed clean-filter configuration is rejected before deployment"
ok test ! -e "$UPDATE_MARKER" "clean-filter bypass performs no updater side effect"
ok grep -Fq 'unreviewed clean/smudge filter' "$OUTPUT" "clean-filter failure is explicit"

setup_case remote-smudge-filter
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
FILTER_SCRIPT="$CASE_DIR/filter.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf smudge >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'cat' >"$FILTER_SCRIPT"
chmod +x "$FILTER_SCRIPT"
printf '%s\n' 'safe.txt filter=execute-change' >"$TARGET/.git/info/attributes"
git -C "$TARGET" config filter.execute-change.clean cat
git -C "$TARGET" config filter.execute-change.smudge "$FILTER_SCRIPT"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "unreviewed smudge driver is rejected before fast-forward checkout"
ok test ! -e "$UPDATE_MARKER" "smudge-filter bypass performs no updater side effect"
ok test ! -e "$UNREVIEWED_MARKER" "smudge driver is never executed"
ok grep -Fq 'unreviewed clean/smudge filter' "$OUTPUT" "smudge-filter failure is explicit"

setup_case remote-info-exclude
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
mkdir -p "$TARGET/backend/cmd/vedetta"
printf '%s\n' unreviewed >"$TARGET/backend/cmd/vedetta/hidden.go"
printf '%s\n' 'backend/cmd/vedetta/hidden.go' >>"$TARGET/.git/info/exclude"
ok test -z "$(git -C "$TARGET" ls-files --others --exclude-standard)" "info/exclude hides an untracked build input from ordinary Git"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "repository-local exclude metadata cannot hide a build input"
ok test ! -e "$UPDATE_MARKER" "info-exclude bypass performs no updater side effect"
ok grep -Fq 'untracked, non-ignored files' "$OUTPUT" "info-exclude failure is explicit"

setup_case stale-history
commit_file "$LOCAL" lab.txt 'LAB_LEAK' B-add
B_LEAK="$(git -C "$LOCAL" rev-parse HEAD)"
git -C "$LOCAL" rm -q lab.txt
git -C "$LOCAL" commit -qm C-delete
C_DELETE="$(git -C "$LOCAL" rev-parse HEAD)"
git -C "$LOCAL" push -qu "$REMOTE_NAME" HEAD:refs/heads/main
git --git-dir="$BARE" update-ref refs/heads/main "$A_CASE"
commit_file "$LOCAL" safe.txt safe D
run_deploy
ok "test" "$DEPLOY_RC" -ne 0 "stale tracking cannot hide add-then-delete history"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$A_CASE" "failed history scan publishes nothing"
ok "test" ! -e "$UPDATE_MARKER" "failed history scan runs no remote update"
ok grep -q "$A_CASE..$(git -C "$LOCAL" rev-parse HEAD)" "$SCAN_LOG" "fresh destination tip defines scanned history"

setup_case observation-fetch-race
commit_file "$LOCAL" lab.txt 'LAB_LEAK' B-add
git -C "$LOCAL" rm -q lab.txt
git -C "$LOCAL" commit -qm C-delete
C_DELETE="$(git -C "$LOCAL" rev-parse HEAD)"
commit_file "$LOCAL" safe.txt safe D
FETCH_RACE="$CASE_DIR/fetch-race.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    '"$VEDETTA_TEST_REAL_GIT" -C "$VEDETTA_TEST_LOCAL" push -q origin "$VEDETTA_TEST_RACE_COMMIT:refs/heads/main"' >"$FETCH_RACE"
chmod +x "$FETCH_RACE"
VEDETTA_TEST_FETCH_RACE="$FETCH_RACE"
VEDETTA_TEST_RACE_COMMIT="$C_DELETE"
export VEDETTA_TEST_RACE_COMMIT
run_deploy
ok test "$DEPLOY_RC" -ne 0 "destination movement between observation and fetch fails closed"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$C_DELETE" "observation/fetch race never publishes reviewed tip over new remote state"
ok grep -q 'moved between inspection and fetch' "$OUTPUT" "observation/fetch race has explicit diagnostic"
ok test ! -s "$SSH_LOG" "observation/fetch race never contacts deployment host"
unset VEDETTA_TEST_RACE_COMMIT

setup_case split-push-url
commit_file "$LOCAL" lab.txt 'LAB_LEAK' B-add
git -C "$LOCAL" rm -q lab.txt
git -C "$LOCAL" commit -qm C-delete
C_DELETE="$(git -C "$LOCAL" rev-parse HEAD)"
commit_file "$LOCAL" safe.txt safe D
FETCH_MIRROR="$CASE_DIR/fetch-mirror.git"
git init -q --bare --initial-branch=main "$FETCH_MIRROR"
git -C "$LOCAL" push -qu "$FETCH_MIRROR" "$C_DELETE:refs/heads/main"
git -C "$LOCAL" remote set-url origin "$FETCH_MIRROR"
git -C "$LOCAL" remote set-url --push origin "$BARE"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "distinct fetch mirror cannot hide push-destination history"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$A_CASE" "split push URL publishes nothing when destination history fails"
ok test ! -s "$SSH_LOG" "split push URL failure never contacts deployment host"

setup_case local-push-helper-url-scheme
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf local-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-foo"
chmod +x "$BIN/git-remote-foo"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" 'foo://example.invalid/repository'
git -C "$LOCAL" config --local protocol.foo.allow always
run_deploy
ok test "$DEPLOY_RC" -ne 0 "local unknown push URI fails closed before destination inspection"
ok test ! -e "$UNREVIEWED_MARKER" "local unknown push URI never executes its remote helper"
ok test ! -s "$SCAN_LOG" "local unknown push URI reaches no sanitation scan"
ok test ! -s "$SSH_LOG" "local unknown push URI reaches no deployment host"
ok grep -Fq 'explicit supported URL or absolute path' "$OUTPUT" "local unknown push URI has an explicit diagnostic"

setup_case local-push-helper-double-colon
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf local-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-foo"
chmod +x "$BIN/git-remote-foo"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" 'foo::repository'
git -C "$LOCAL" config --local protocol.foo.allow always
run_deploy
ok test "$DEPLOY_RC" -ne 0 "local transport double-colon push URL fails closed"
ok test ! -e "$UNREVIEWED_MARKER" "local double-colon push URL never executes its remote helper"
ok test ! -s "$SCAN_LOG" "local double-colon push URL reaches no sanitation scan"
ok test ! -s "$SSH_LOG" "local double-colon push URL reaches no deployment host"
ok grep -Fq 'explicit supported URL or absolute path' "$OUTPUT" "local double-colon push URL has an explicit diagnostic"

setup_case local-push-helper-nested-rewrite
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf local-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-foo"
chmod +x "$BIN/git-remote-foo"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" 'https://safe.example/repository'
git -C "$LOCAL" config --local 'url.ssh://safe.example/.insteadOf' 'https://safe.example/'
git -C "$LOCAL" config --local 'url.foo::.insteadOf' 'ssh://safe.example/'
git -C "$LOCAL" config --local protocol.foo.allow always
run_deploy
ok test "$DEPLOY_RC" -ne 0 "nested local URL rewrite fails closed before native transport"
ok test ! -e "$UNREVIEWED_MARKER" "nested local URL rewrite never executes its remote helper"
ok test ! -s "$SCAN_LOG" "nested local URL rewrite reaches no sanitation scan"
ok test ! -s "$SSH_LOG" "nested local URL rewrite reaches no deployment host"
ok grep -Fq 'subject to another configured Git URL rewrite' "$OUTPUT" "nested rewrite has an explicit diagnostic"

setup_case local-push-helper-allowed-name-rewrite
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf local-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-ssh"
chmod +x "$BIN/git-remote-ssh"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" 'https://safe.example/repository'
git -C "$LOCAL" config --local 'url.ssh://stage.example/.insteadOf' 'https://safe.example/'
git -C "$LOCAL" config --local 'url.ssh::.insteadOf' 'ssh://stage.example/'
run_deploy
ok test "$DEPLOY_RC" -ne 0 "nested rewrite to an allowed-name helper fails closed"
ok test ! -e "$UNREVIEWED_MARKER" "allowed-name remote helper is never executed"
ok test ! -s "$SCAN_LOG" "allowed-name helper rewrite reaches no sanitation scan"
ok test ! -s "$SSH_LOG" "allowed-name helper rewrite reaches no deployment host"
ok grep -Fq 'subject to another configured Git URL rewrite' "$OUTPUT" "allowed-name rewrite has an explicit diagnostic"

setup_case local-push-blinded-config-inspection
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf local-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-ssh"
chmod +x "$BIN/git-remote-ssh"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" 'https://safe.example/repository'
git -C "$LOCAL" config --local 'url.ssh://stage.example/.insteadOf' 'https://safe.example/'
git -C "$LOCAL" config --local 'url.ssh::.insteadOf' 'ssh://stage.example/'
GIT_CONFIG=/dev/null
export GIT_CONFIG
run_deploy
unset GIT_CONFIG
ok test "$DEPLOY_RC" -ne 0 "ambient GIT_CONFIG cannot blind nested-rewrite inspection"
ok test ! -e "$UNREVIEWED_MARKER" "blinded-config attempt never executes its allowed-name helper"
ok test ! -s "$SCAN_LOG" "blinded-config attempt reaches no sanitation scan"
ok test ! -s "$SSH_LOG" "blinded-config attempt reaches no deployment host"
ok grep -Fq 'subject to another configured Git URL rewrite' "$OUTPUT" "blinded-config attempt has an explicit diagnostic"

setup_case local-push-split-rewrite
commit_file "$LOCAL" safe.txt safe B
SECOND_PUSH="$CASE_DIR/second-push.git"
git init -q --bare --initial-branch=main "$SECOND_PUSH"
git -C "$LOCAL" push -q "$SECOND_PUSH" "$A_CASE:refs/heads/main"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" "file://$BARE"
git -C "$LOCAL" config --local "url.file://$SECOND_PUSH.pushInsteadOf" "file://$BARE"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "push-only rewrite cannot split inspection from publication"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$A_CASE" "inspected repository receives no rewritten publication"
is "$(git --git-dir="$SECOND_PUSH" rev-parse refs/heads/main)" "$A_CASE" "pushInsteadOf destination receives no reviewed commit"
ok test ! -s "$SCAN_LOG" "split rewrite is rejected before sanitation"
ok test ! -s "$SSH_LOG" "split rewrite is rejected before deployment host access"
ok grep -Fq 'subject to another configured Git URL rewrite' "$OUTPUT" "split rewrite has an explicit diagnostic"

setup_case local-push-ambient-exec-path
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf local-helper >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$BIN/git-remote-https"
chmod +x "$BIN/git-remote-https"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" 'https://127.0.0.1:1/repository'
GIT_EXEC_PATH="$BIN"
export GIT_EXEC_PATH
run_deploy
unset GIT_EXEC_PATH
ok test "$DEPLOY_RC" -ne 0 "valid HTTPS URL fails normally when its endpoint is unavailable"
ok test ! -e "$UNREVIEWED_MARKER" "ambient Git executable path cannot replace a native transport helper"
ok test ! -s "$SCAN_LOG" "unavailable HTTPS destination reaches no sanitation scan"
ok test ! -s "$SSH_LOG" "unavailable HTTPS destination reaches no deployment host"

setup_case local-push-ssh-command-overrides
commit_file "$LOCAL" safe.txt safe B
SSH_EXECUTOR="$CASE_DIR/ssh-executor.sh"
PINNED_SSH_LOG="$CASE_DIR/pinned-ssh.log"
PINNED_SSH_ENV_LOG="$CASE_DIR/pinned-ssh.env"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf local-ssh >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$SSH_EXECUTOR"
chmod +x "$SSH_EXECUTOR"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf "%s\n" "$@" >"${VEDETTA_TEST_PINNED_SSH_LOG:?}"' \
    'printf "%s\n" \' \
    '  "GIT_SSH_COMMAND=${GIT_SSH_COMMAND-}" \' \
    '  "GIT_SSH_VARIANT=${GIT_SSH_VARIANT-}" \' \
    '  "GIT_ASKPASS=${GIT_ASKPASS-}" \' \
    '  "SSH_ASKPASS=${SSH_ASKPASS-}" \' \
    '  "SSH_ASKPASS_REQUIRE=${SSH_ASKPASS_REQUIRE-}" \' \
    '  "GIT_TERMINAL_PROMPT=${GIT_TERMINAL_PROMPT-}" \' \
    '  >"${VEDETTA_TEST_PINNED_SSH_ENV_LOG:?}"' \
    'exit 255' >"$BIN/ssh"
chmod +x "$BIN/ssh"
: >"$PINNED_SSH_LOG"
: >"$PINNED_SSH_ENV_LOG"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" 'ssh://127.0.0.1:1/repository'
git -C "$LOCAL" config --local core.sshCommand "$SSH_EXECUTOR"
git -C "$LOCAL" config --local core.askPass "$SSH_EXECUTOR"
GIT_SSH="$SSH_EXECUTOR"
GIT_SSH_COMMAND="$SSH_EXECUTOR"
GIT_SSH_VARIANT=plink
GIT_ASKPASS="$SSH_EXECUTOR"
SSH_ASKPASS="$SSH_EXECUTOR"
SSH_ASKPASS_REQUIRE=force
GIT_CONFIG_COUNT=2
GIT_CONFIG_KEY_0=core.sshCommand
GIT_CONFIG_VALUE_0="$SSH_EXECUTOR"
GIT_CONFIG_KEY_1=ssh.variant
GIT_CONFIG_VALUE_1=plink
VEDETTA_TEST_PINNED_SSH_LOG="$PINNED_SSH_LOG"
VEDETTA_TEST_PINNED_SSH_ENV_LOG="$PINNED_SSH_ENV_LOG"
ssh() {
    printf exported-ssh >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"
    return 98
}
export -f ssh
export GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_ASKPASS SSH_ASKPASS \
    SSH_ASKPASS_REQUIRE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 \
    GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1 VEDETTA_TEST_PINNED_SSH_LOG \
    VEDETTA_TEST_PINNED_SSH_ENV_LOG
run_deploy
unset -f ssh
unset GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_ASKPASS SSH_ASKPASS \
    SSH_ASKPASS_REQUIRE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 \
    GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1 VEDETTA_TEST_PINNED_SSH_LOG \
    VEDETTA_TEST_PINNED_SSH_ENV_LOG
ok test "$DEPLOY_RC" -ne 0 "unavailable SSH endpoint fails through the pinned native client"
ok test ! -e "$UNREVIEWED_MARKER" "ambient, repository, and command-scope SSH executors are never selected"
ok grep -Fxq -- '-oBatchMode=yes' "$PINNED_SSH_LOG" "Git invokes the pinned non-interactive SSH command"
ok grep -Fxq -- '-p' "$PINNED_SSH_LOG" "Git uses OpenSSH argument conventions"
ok not_grep '-P' "$PINNED_SSH_LOG" "ambient Plink argument conventions are ignored"
is "$(cat "$PINNED_SSH_ENV_LOG")" \
    $'GIT_SSH_COMMAND='"$BIN"$'/ssh -oBatchMode=yes\nGIT_SSH_VARIANT=ssh\nGIT_ASKPASS=/bin/false\nSSH_ASKPASS=/bin/false\nSSH_ASKPASS_REQUIRE=never\nGIT_TERMINAL_PROMPT=0' \
    "the pinned SSH process receives only non-interactive askpass controls"
ok test ! -s "$SCAN_LOG" "unavailable SSH destination reaches no sanitation scan"
ok test ! -s "$SSH_LOG" "unavailable SSH destination reaches no deployment host"

setup_case local-file-push-url
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" "file://$BARE"
run_deploy
is "$DEPLOY_RC" "0" "explicit file push URL remains supported"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$B_CASE" "file push URL publishes the reviewed SHA"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "file push URL deploys the reviewed SHA"

setup_case local-one-step-url-alias
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" 'https://alias.example/repository.git'
git -C "$LOCAL" config --local "url.file://$CASE_DIR/.insteadOf" 'https://alias.example/'
git -C "$LOCAL" config --local 'url.ssh://unused.example/.insteadOf' 'https://unused.example/'
run_deploy
is "$DEPLOY_RC" "0" "ordinary one-step URL alias remains supported"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$B_CASE" "one-step URL alias publishes to the captured destination"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "one-step URL alias deploys the reviewed SHA"

setup_case local-push-remote-name
commit_file "$LOCAL" safe.txt safe B
git -C "$LOCAL" remote add mirror "$BARE"
git -C "$LOCAL" remote set-url --push "$REMOTE_NAME" mirror
run_deploy
ok test "$DEPLOY_RC" -ne 0 "local push URL cannot defer destination resolution through another remote name"
ok test ! -s "$SCAN_LOG" "local remote-name indirection reaches no sanitation scan"
ok test ! -s "$SSH_LOG" "local remote-name indirection reaches no deployment host"
ok grep -Fq 'explicit supported URL or absolute path' "$OUTPUT" "local remote-name indirection has an explicit diagnostic"

setup_case multiple-push-urls
commit_file "$LOCAL" safe.txt safe B
SECOND_PUSH="$CASE_DIR/second-push.git"
git init -q --bare --initial-branch=main "$SECOND_PUSH"
git -C "$LOCAL" remote set-url --add --push origin "$BARE"
git -C "$LOCAL" remote set-url --add --push origin "$SECOND_PUSH"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "multiple push destinations fail closed"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$A_CASE" "multiple push URLs publish nothing to the first destination"
ok grep -q 'exactly one supported push URL' "$OUTPUT" "multiple push URLs have explicit diagnostic"

setup_case slash-remote team/upstream
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
run_deploy
is "$DEPLOY_RC" "0" "local remote name containing slash is resolved from Git config"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "deployment clone may use a different remote name"

setup_case local-head-race
commit_file "$LOCAL" safe.txt safe B
PINNED="$(git -C "$LOCAL" rev-parse HEAD)"
hook="$(git -C "$LOCAL" rev-parse --absolute-git-dir)/hooks/pre-push"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -e' \
    'git -C "$VEDETTA_TEST_LOCAL" commit --allow-empty -qm concurrent-local-head' >"$hook"
chmod +x "$hook"
run_deploy
MOVED_HEAD="$(git -C "$LOCAL" rev-parse HEAD)"
ok "test" "$MOVED_HEAD" != "$PINNED" "pre-push hook moved local HEAD during deployment"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$PINNED" "push names immutable scanned SHA, not moved HEAD"
is "$(cat "$UPDATE_MARKER")" "$PINNED" "remote update remains pinned after local HEAD race"

setup_case lease-race
commit_file "$LOCAL" safe.txt safe B
git clone -q "$BARE" "$RACER"
git_identity "$RACER"
commit_file "$RACER" racer.txt remote-change R
RACER_HEAD="$(git -C "$RACER" rev-parse HEAD)"
hook="$(git -C "$LOCAL" rev-parse --absolute-git-dir)/hooks/pre-push"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -e' \
    'git -C "$VEDETTA_TEST_RACER" push -q origin HEAD:refs/heads/main' >"$hook"
chmod +x "$hook"
VEDETTA_TEST_RACER="$RACER"
run_deploy
ok "test" "$DEPLOY_RC" -ne 0 "exact expected-tip lease rejects pre-push remote race"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$RACER_HEAD" "lease race preserves concurrent remote commit"
ok "test" ! -s "$SSH_LOG" "lease failure never contacts deployment host"

setup_case post-push-race
commit_file "$LOCAL" safe.txt safe B
PINNED="$(git -C "$LOCAL" rev-parse HEAD)"
git clone -q "$BARE" "$RACER"
git_identity "$RACER"
POST_RACE="$CASE_DIR/post-race.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'git -C "$VEDETTA_TEST_RACER" fetch -q origin main' \
    'git -C "$VEDETTA_TEST_RACER" merge -q --ff-only origin/main' \
    'printf "%s\n" after >"$VEDETTA_TEST_RACER/after.txt"' \
    'git -C "$VEDETTA_TEST_RACER" add after.txt' \
    'git -C "$VEDETTA_TEST_RACER" commit -qm after-push-race' \
    'git -C "$VEDETTA_TEST_RACER" push -q origin HEAD:refs/heads/main' >"$POST_RACE"
chmod +x "$POST_RACE"
VEDETTA_TEST_RACER="$RACER"
VEDETTA_TEST_POST_PUSH_RACE="$POST_RACE"
run_deploy
ok "test" "$DEPLOY_RC" -ne 0 "remote movement after push is rejected before update"
ok "test" ! -e "$UPDATE_MARKER" "post-push race deploys neither reviewed nor moving tip"
ok grep -q 'Published branch moved after review' "$OUTPUT" "post-push mismatch has an explicit diagnostic"

setup_case wrong-branch
commit_file "$LOCAL" safe.txt safe B
git -C "$TARGET" switch -qc other
run_deploy
ok "test" "$DEPLOY_RC" -ne 0 "deployment host on wrong branch is rejected"
ok "test" ! -e "$UPDATE_MARKER" "wrong branch runs no update"

setup_case dirty-remote
commit_file "$LOCAL" safe.txt safe B
printf '%s\n' dirty >>"$TARGET/README.md"
run_deploy
ok "test" "$DEPLOY_RC" -ne 0 "dirty remote tracked worktree is rejected"
ok "test" ! -e "$UPDATE_MARKER" "dirty remote runs no update"

setup_case hidden-local-assume-unchanged
commit_file "$LOCAL" safe.txt safe B
git -C "$LOCAL" update-index --assume-unchanged README.md
printf '%s\n' hidden-local-change >"$LOCAL/README.md"
ok git -C "$LOCAL" diff --quiet -- "assume-unchanged masks a modified local tracked file from ordinary diff"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "local assume-unchanged state is rejected before publication"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$A_CASE" "hidden local change publishes nothing"
ok test ! -s "$SSH_LOG" "hidden local change never contacts deployment host"
ok grep -Fq 'skip-worktree/assume-unchanged index flags' "$OUTPUT" "hidden local state has an explicit diagnostic"

setup_case hidden-remote-skip-worktree
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
git -C "$TARGET" update-index --skip-worktree README.md
printf '%s\n' hidden-remote-change >"$TARGET/README.md"
ok git -C "$TARGET" diff --quiet -- "skip-worktree masks a modified remote tracked file from ordinary diff"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "remote skip-worktree state is rejected before checkout update"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$B_CASE" "reviewed SHA may publish before remote hidden-state rejection"
is "$(git -C "$TARGET" rev-parse HEAD)" "$A_CASE" "remote hidden state prevents checkout movement"
ok test ! -e "$UPDATE_MARKER" "remote hidden state runs no update"
ok grep -Fq 'skip-worktree/assume-unchanged index flags' "$OUTPUT" "hidden remote state has an explicit diagnostic"

setup_case untracked-remote-source
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
mkdir -p "$TARGET/backend"
printf '%s\n' 'package injected' >"$TARGET/backend/injected.go"
ok git -C "$TARGET" diff --quiet -- "ordinary tracked diff ignores an untracked remote source file"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "remote untracked source is rejected before checkout update"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$B_CASE" "reviewed SHA may publish before remote untracked-source rejection"
is "$(git -C "$TARGET" rev-parse HEAD)" "$A_CASE" "remote untracked source prevents checkout movement"
ok test ! -e "$UPDATE_MARKER" "remote untracked source runs no update"
ok grep -Fq 'untracked, non-ignored files' "$OUTPUT" "remote untracked source has an explicit diagnostic"

setup_case ignored-remote-source
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
mkdir -p "$TARGET/backend/cmd/vedetta"
printf '%s\n' 'package main' >"$TARGET/backend/cmd/vedetta/secret_inject.go"
ok git -C "$TARGET" check-ignore -q backend/cmd/vedetta/secret_inject.go "broad secret rule hides a shipped backend source file"
ok test -z "$(git -C "$TARGET" ls-files --others --exclude-standard)" "nonignored-file check misses ignored backend source"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "remote ignored backend source is rejected before checkout update"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$B_CASE" "reviewed SHA may publish before remote ignored-source rejection"
is "$(git -C "$TARGET" rev-parse HEAD)" "$A_CASE" "remote ignored source prevents checkout movement"
ok test ! -e "$UPDATE_MARKER" "remote ignored source runs no update"
ok grep -Fq 'ignored build input' "$OUTPUT" "remote ignored source has an explicit diagnostic"

setup_case ignored-safe-artifacts
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
mkdir -p "$TARGET/backend" "$TARGET/sensor" "$TARGET/telemetry" \
    "$TARGET/frontend/node_modules/example" "$TARGET/frontend/dist"
printf '%s\n' binary >"$TARGET/backend/vedetta"
printf '%s\n' binary >"$TARGET/sensor/vedetta-sensor"
printf '%s\n' binary >"$TARGET/telemetry/telemetry"
printf '%s\n' module >"$TARGET/frontend/node_modules/example/index.js"
printf '%s\n' built >"$TARGET/frontend/dist/index.html"
printf '%s\n' runtime >"$TARGET/frontend/.env.placeholder"
run_deploy
is "$DEPLOY_RC" "0" "reviewed ignored build-artifact allowlist permits exact deployment"
is "$(git -C "$TARGET" rev-parse HEAD)" "$B_CASE" "safe ignored artifacts do not prevent reviewed checkout update"
is "$(cat "$UPDATE_MARKER")" "$B_CASE" "safe ignored artifacts still update at reviewed SHA"

setup_case ignored-empty-remote-vendor
commit_file "$LOCAL" safe.txt safe B
B_CASE="$(git -C "$LOCAL" rev-parse HEAD)"
mkdir -p "$TARGET/backend/vendor"
ok git -C "$TARGET" check-ignore -q backend/vendor/ "vendor rule hides an empty backend vendor directory"
ok test -z "$(git -C "$TARGET" ls-files --others --ignored --exclude-standard -- backend/vendor)" "file-only ignored scan misses an empty vendor directory"
run_deploy
ok test "$DEPLOY_RC" -ne 0 "remote empty vendor directory is rejected before checkout update"
is "$(git --git-dir="$BARE" rev-parse refs/heads/main)" "$B_CASE" "reviewed SHA may publish before remote empty-vendor rejection"
is "$(git -C "$TARGET" rev-parse HEAD)" "$A_CASE" "remote empty vendor directory prevents checkout movement"
ok test ! -e "$UPDATE_MARKER" "remote empty vendor directory runs no update"
ok grep -Fq 'ignored build directory' "$OUTPUT" "remote empty vendor directory has an explicit diagnostic"

setup_case new-branch
git -C "$LOCAL" switch -qc feature
git -C "$LOCAL" config branch.feature.remote origin
commit_file "$LOCAL" feature.txt safe B
NEW_HEAD="$(git -C "$LOCAL" rev-parse HEAD)"
git -C "$TARGET" switch -qc feature
run_deploy
is "$DEPLOY_RC" "0" "new branch uses freshly fetched trusted main baseline"
is "$(git --git-dir="$BARE" rev-parse refs/heads/feature)" "$NEW_HEAD" "new branch lease creates exact reviewed ref"
is "$(cat "$UPDATE_MARKER")" "$NEW_HEAD" "new branch deployment reaches exact SHA"

# These controls are duplicated in the checkout verifier and immutable updater
# launcher. Keep both copies locked, together with the pinned updater wrapper.
is "$(grep -Fc 'GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1' "$DEPLOY_SCRIPT")" "3" "local publisher and both remote Git wrappers disable replacement objects and lazy fetch"
is "$(grep -Fc -- '-u GIT_CONFIG_PARAMETERS -u GIT_EXEC_PATH -u GIT_ALLOW_PROTOCOL' "$DEPLOY_SCRIPT")" "2" "both remote Git wrappers discard ambient executor and protocol overrides"
is "$(grep -Fc 'reject_unsafe_git_metadata' "$DEPLOY_SCRIPT")" "4" "both remote sessions define and invoke Git metadata validation"
is "$(grep -Fc 'objects/info/alternates' "$DEPLOY_SCRIPT")" "2" "both remote sessions reject alternate object storage"
is "$(grep -Fc 'remote.*.uploadpack' "$DEPLOY_SCRIPT")" "2" "both remote sessions reject configured upload-pack executors"
is "$(grep -Fc 'protocol.allow|protocol.*.allow' "$DEPLOY_SCRIPT")" "2" "both remote sessions reject repository-local protocol permissions"
ok grep -Fq -- '--no-recurse-submodules --no-auto-maintenance' "$DEPLOY_SCRIPT" "remote fetch disables submodules and automatic maintenance"
ok grep -Fq -- '--upload-pack=git-upload-pack "$remote_url"' "$DEPLOY_SCRIPT" "remote fetch pins the upload-pack command name"
ok grep -Fq -- 'git merge --ff-only --no-verify-signatures --no-gpg-sign --no-autostash' "$DEPLOY_SCRIPT" "remote merge disables configured signature and autostash execution"
is "$(grep -Fc 'GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1' "$UPDATE_SCRIPT")" "1" "pinned updater disables replacement objects and lazy fetch"
is "$(grep -Fc -- '-u GIT_CONFIG_PARAMETERS -u GIT_EXEC_PATH -u GIT_ALLOW_PROTOCOL' "$UPDATE_SCRIPT")" "1" "pinned updater discards ambient executor and protocol overrides"
is "$(grep -Fc 'objects/info/alternates' "$UPDATE_SCRIPT")" "1" "pinned updater rejects alternate object storage"
is "$(grep -Fc 'remote.*.uploadpack' "$UPDATE_SCRIPT")" "1" "pinned updater rejects configured upload-pack executors"
is "$(grep -Fc 'protocol.allow|protocol.*.allow' "$UPDATE_SCRIPT")" "1" "pinned updater rejects repository-local protocol permissions"

# ---- Real update-all pinned revision behavior -------------------------------

setup_update_case() {
    local name="$1"
    UPDATE_DIR="$TMP/update-$name"
    UPDATE_BARE="$UPDATE_DIR/repository.git"
    UPDATE_SEED="$UPDATE_DIR/seed"
    UPDATE_WORK="$UPDATE_DIR/work"
    UPDATE_RACER="$UPDATE_DIR/racer"
    UPDATE_BIN="$UPDATE_DIR/bin"
    UPDATE_LOG="$UPDATE_DIR/commands.log"
    UPDATE_OUTPUT="$UPDATE_DIR/output.log"
    mkdir -p "$UPDATE_SEED/scripts/lib" "$UPDATE_SEED/sensor" \
        "$UPDATE_SEED/backend" "$UPDATE_SEED/frontend" \
        "$UPDATE_SEED/collector" "$UPDATE_SEED/telemetry" \
        "$UPDATE_SEED/siem/migrations" "$UPDATE_BIN"
    git init -q --bare --initial-branch=main "$UPDATE_BARE"
    git init -q -b main "$UPDATE_SEED"
    git_identity "$UPDATE_SEED"
    cp "$UPDATE_SCRIPT" "$UPDATE_SEED/scripts/update-all.sh"
    cp "$ROOT/scripts/lib/port-config.sh" "$UPDATE_SEED/scripts/lib/port-config.sh"
    printf '%s\n' \
        'runtime.ignored' \
        '*secret*' \
        'vendor/' \
        '/backend/vedetta' \
        '/sensor/vedetta-sensor' \
        '/telemetry/telemetry' \
        'docker-compose.override.yml' \
        'frontend/node_modules/' \
        'frontend/dist/' \
        'frontend/.env*' >"$UPDATE_SEED/.gitignore"
    printf '%s\n' base >"$UPDATE_SEED/README.md"
    for tracked_root in backend frontend collector telemetry; do
        printf '%s\n' tracked >"$UPDATE_SEED/$tracked_root/.tracked"
    done
    printf '%s\n' tracked >"$UPDATE_SEED/siem/migrations/.tracked"
    printf '%s\n' 'services: {}' >"$UPDATE_SEED/docker-compose.yml"
    printf '%s\n' 'module example.invalid/pinned-update-test' >"$UPDATE_SEED/sensor/go.mod"
    git -C "$UPDATE_SEED" add .
    git -C "$UPDATE_SEED" commit -qm base
    UPDATE_A="$(git -C "$UPDATE_SEED" rev-parse HEAD)"
    git -C "$UPDATE_SEED" remote add origin "$UPDATE_BARE"
    git -C "$UPDATE_SEED" push -qu -u origin main
    git clone -q "$UPDATE_BARE" "$UPDATE_WORK"
    git clone -q "$UPDATE_BARE" "$UPDATE_RACER"
    git_identity "$UPDATE_WORK"
    git_identity "$UPDATE_RACER"
    commit_file "$UPDATE_RACER" remote.txt advanced remote-advance
    UPDATE_B="$(git -C "$UPDATE_RACER" rev-parse HEAD)"
    git -C "$UPDATE_RACER" push -qu origin HEAD:refs/heads/main
    # Make the advanced object available without moving the checked-out A tip;
    # the race shim can now perform a real fast-forward between verifications.
    git -C "$UPDATE_WORK" fetch -q origin main

    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'printf "sudo %s\n" "$*" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        'if [[ "$1" == "-u" ]]; then shift 2; fi' \
        'command="$1"; shift' \
        'case "$command" in' \
        '  git) exec "${VEDETTA_TEST_REAL_GIT:?}" "$@" ;;' \
        '  chown)' \
        '    # Emulate root ownership: the unprivileged test account must not be' \
        '    # able to write the tree after this otherwise-no-op ownership change.' \
        '    if [[ "${@: -1}" == "/usr/local/bin/vedetta-sensor" || "${@: -1}" == "/usr/local/bin/vedetta-sensor.tmp.TEST" ]]; then exit 0; fi' \
        '    chmod -R a-w "${@: -1}"' \
        '    exit 0' \
        '    ;;' \
        '  chmod)' \
        '    if [[ "${@: -1}" == "/usr/local/bin/vedetta-sensor.tmp.TEST" ]]; then exit 0; fi' \
        '    if [[ "${1:-}" == "-R" && "${2:-}" == "go-w" ]]; then exec chmod -R a-w "${@: -1}"; fi' \
        '    if [[ "${1:-}" == "0755" && "${@: -1}" == *"vedetta-pinned."* ]]; then exec chmod 0555 "${@: -1}"; fi' \
        '    exec chmod "$@"' \
        '    ;;' \
        '  cmp)' \
        '    [[ "${VEDETTA_TEST_SENSOR_STAGE_MISMATCH:-}" == "1" ]] && exit 1' \
        '    exit 0' \
        '    ;;' \
        '  stat)' \
        '    # Production probes GNU then BSD stat; model root ownership while' \
        '    # preserving logical modes after the shim removes owner-write bits.' \
        '    format="${2:-}"; candidate="${@: -1}"' \
        '    if [[ "$format" == "%u" || "$format" == "%g" ]]; then' \
        '      if [[ "$format" == "%u" && -n "${VEDETTA_TEST_OWNER_MISMATCH_SUFFIX:-}" && "$candidate" == *"$VEDETTA_TEST_OWNER_MISMATCH_SUFFIX" ]]; then printf "%s\n" 501; else printf "%s\n" 0; fi' \
        '      exit 0' \
        '    fi' \
        '    if [[ "$format" == "%a" || "$format" == "%Lp" ]]; then' \
        '      if [[ -n "${VEDETTA_TEST_MODE_MISMATCH_SUFFIX:-}" && "$candidate" == *"$VEDETTA_TEST_MODE_MISMATCH_SUFFIX" ]]; then printf "%s\n" 444; exit 0; fi' \
        '      if [[ "$candidate" == "/usr/local/bin/vedetta-sensor" || "$candidate" == "/usr/local/bin/vedetta-sensor.tmp.TEST" ]]; then printf "%s\n" 755; exit 0; fi' \
        '      if /usr/bin/stat -c "%a" "$candidate" >/dev/null 2>&1; then' \
        '        actual="$(/usr/bin/stat -c "%a" "$candidate")"' \
        '      else' \
        '        actual="$(/usr/bin/stat -f "%Lp" "$candidate")"' \
        '      fi' \
        '      if [[ -d "$candidate" && "$actual" == "555" ]]; then actual=755; fi' \
        '      if [[ -f "$candidate" && "$actual" == "444" ]]; then actual=644; fi' \
        '      if [[ -f "$candidate" && "$actual" == "555" ]]; then actual=755; fi' \
        '      printf "%s\n" "$actual"' \
        '      exit 0' \
        '    fi' \
        '    exit 1' \
        '    ;;' \
        '  test)' \
        '    if [[ "${1:-}" == "-f" && ( "${2:-}" == "/usr/local/bin/vedetta-sensor" || "${2:-}" == "/usr/local/bin/vedetta-sensor.tmp.TEST" ) ]]; then exit 0; fi' \
        '    if [[ "${1:-}" == "-L" && ( "${2:-}" == "/usr/local/bin/vedetta-sensor" || "${2:-}" == "/usr/local/bin/vedetta-sensor.tmp.TEST" ) ]]; then exit 1; fi' \
        '    if [[ "${1:-}" == "-w" || ( "${1:-}" == "!" && "${2:-}" == "-w" ) ]]; then' \
        '      if [[ "${1:-}" == "-w" ]]; then candidate="${2:-}"; negated=0; else candidate="${3:-}"; negated=1; fi' \
        '      if [[ -n "${VEDETTA_TEST_TEST_ERROR_PATH:-}" && "$candidate" == "$VEDETTA_TEST_TEST_ERROR_PATH" ]]; then exit 125; fi' \
        '      writable=1' \
        '      if [[ -n "${VEDETTA_TEST_WRITABLE_SENSOR_PATH:-}" &&' \
        '            "$candidate" == "$VEDETTA_TEST_WRITABLE_SENSOR_PATH" ]]; then writable=0; fi' \
        '      if [[ -n "${VEDETTA_TEST_WRITABLE_SNAPSHOT_SUFFIX:-}" &&' \
        '            "$candidate" == *"$VEDETTA_TEST_WRITABLE_SNAPSHOT_SUFFIX" ]]; then writable=0; fi' \
        '      if [[ -n "${VEDETTA_TEST_WRITABLE_SENSOR_STAGE:-}" &&' \
        '            "$candidate" == "$VEDETTA_TEST_WRITABLE_SENSOR_STAGE" ]]; then writable=0; fi' \
        '      if [[ "$negated" == "1" ]]; then [[ "$writable" == "0" ]] && exit 1 || exit 0; fi' \
        '      exit "$writable"' \
        '    fi' \
        '    exec test "$@"' \
        '    ;;' \
        '  env)' \
        '    if [[ "$*" == *"/bin/ls -lde"* ]]; then' \
        '      candidate="${@: -1}"' \
        '      printf "%s\n" "dr-xr-xr-x root wheel $candidate"' \
        '      if [[ -n "${VEDETTA_TEST_ACL_PATH:-}" && "$candidate" == "$VEDETTA_TEST_ACL_PATH" ]]; then' \
        '        printf "%s\n" " 0: user:test allow add_file,delete_child,writesecurity"' \
        '      fi' \
        '      exit 0' \
        '    fi' \
        '    exec env "$@"' \
        '    ;;' \
        '  mktemp)' \
        '    if [[ "$*" == "/usr/local/bin/vedetta-sensor.tmp.XXXXXX" ]]; then' \
        '      printf "%s\n" /usr/local/bin/vedetta-sensor.tmp.TEST' \
        '      exit 0' \
        '    fi' \
        '    exec mktemp "$@"' \
        '    ;;' \
        '  go)' \
        '    if [[ "${1:-}" == "mod" ]]; then exit 0; fi' \
        '    output=""' \
        '    while (($#)); do' \
        '      if [[ "$1" == "-o" && $# -ge 2 ]]; then output="$2"; shift 2; else shift; fi' \
        '    done' \
        '    [[ -n "$output" ]] || exit 91' \
        '    if [[ "${VEDETTA_TEST_SENSOR_RACE:-}" == "1" ]]; then' \
        '      original="$(cat "${VEDETTA_TEST_UPDATE_WORK:?}/sensor/go.mod")"' \
        '      printf "%s\n" "module example.invalid/malicious-worktree" >"${VEDETTA_TEST_UPDATE_WORK:?}/sensor/go.mod"' \
        '      printf "%s\n" malicious-worktree-binary >"${VEDETTA_TEST_UPDATE_WORK:?}/sensor/vedetta-sensor"' \
        '      if [[ -w "$PWD/go.mod" ]]; then protection=writable; else protection=read-only; fi' \
        '      printf "sensor-build-cwd=%s\n" "$PWD" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        '      printf "sensor-build-snapshot=%s\n" "$protection" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        '      printf "sensor-build-source=%s\n" "$(cat go.mod)" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        '      printf "sensor-built-from:%s\n" "$(cat go.mod)" >"$output"' \
        '      printf "%s\n" "$original" >"${VEDETTA_TEST_UPDATE_WORK:?}/sensor/go.mod"' \
        '    else' \
        '      mkdir -p "$(dirname -- "$output")"' \
        '      printf "sensor-built-from:%s\n" "$(cat go.mod)" >"$output"' \
        '    fi' \
        '    exit 0' \
        '    ;;' \
        '  *) exec "$command" "$@" ;;' \
        'esac' >"$UPDATE_BIN/sudo"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'printf "docker %s\n" "$*" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        'first_file=""; second_file=""; is_build=0' \
        'while (($#)); do' \
        '  if [[ "$1" == "-f" && $# -ge 2 ]]; then' \
        '    if [[ -z "$first_file" ]]; then first_file="$2"; else second_file="$2"; fi' \
        '    shift 2' \
        '  else' \
        '    [[ "$1" == "build" ]] && is_build=1' \
        '    shift' \
        '  fi' \
        'done' \
        'if [[ "$is_build" == "1" && -n "$first_file" ]]; then' \
        '  source_dir="$(dirname -- "$first_file")"' \
        '  if [[ -w "$source_dir/backend/.tracked" ]]; then protection=writable; else protection=read-only; fi' \
        '  if [[ "${VEDETTA_TEST_COMPOSE_RACE:-}" == "1" ]]; then' \
        '    original_source="$(cat "${VEDETTA_TEST_UPDATE_WORK:?}/backend/.tracked")"' \
        '    original_compose="$(cat "${VEDETTA_TEST_UPDATE_WORK:?}/docker-compose.yml")"' \
        '    printf "%s\n" malicious-worktree-context >"${VEDETTA_TEST_UPDATE_WORK:?}/backend/.tracked"' \
        '    printf "%s\n" "services: {backend: {build: /malicious/worktree}}" >"${VEDETTA_TEST_UPDATE_WORK:?}/docker-compose.yml"' \
        '    printf "docker-build-source=%s\n" "$(cat "$source_dir/backend/.tracked")" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        '    printf "docker-build-compose=%s\n" "$(cat "$first_file")" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        '    printf "docker-build-snapshot=%s\n" "$protection" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        '    printf "docker-build-context-count=%s\n" "$(grep -Fc "$source_dir" "$second_file")" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        '    printf "%s\n" "$original_source" >"${VEDETTA_TEST_UPDATE_WORK:?}/backend/.tracked"' \
        '    printf "%s\n" "$original_compose" >"${VEDETTA_TEST_UPDATE_WORK:?}/docker-compose.yml"' \
        '  fi' \
        'fi' \
        'if [[ "${VEDETTA_TEST_DOCKER_BUILD_FAIL:-}" == "1" && "$is_build" == "1" ]]; then exit 17; fi' \
        'if [[ -n "${VEDETTA_TEST_UPDATE_RACE_HEAD:-}" && ! -e "${VEDETTA_TEST_UPDATE_LOG}.raced" ]]; then' \
        '  : >"${VEDETTA_TEST_UPDATE_LOG}.raced"' \
        '  "${VEDETTA_TEST_REAL_GIT:?}" -C "${VEDETTA_TEST_UPDATE_WORK:?}" merge -q --ff-only "$VEDETTA_TEST_UPDATE_RACE_HEAD"' \
        'fi' \
        'exit 0' >"$UPDATE_BIN/docker"
    printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "{\"suppression\":true}"' >"$UPDATE_BIN/curl"
    printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "${VEDETTA_TEST_UNAME:-Linux}"' >"$UPDATE_BIN/uname"
    printf '%s\n' '#!/usr/bin/env bash' 'printf "systemctl %s\n" "$*" >>"${VEDETTA_TEST_UPDATE_LOG:?}"; exit 0' >"$UPDATE_BIN/systemctl"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$UPDATE_BIN/pgrep"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$UPDATE_BIN/sleep"
    printf '%s\n' '#!/usr/bin/env bash' 'printf "cp %s\n" "$*" >>"${VEDETTA_TEST_UPDATE_LOG:?}"; exit 0' >"$UPDATE_BIN/cp"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'printf "install %s\n" "$*" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        'source_path="${@: -2:1}"' \
        'printf "install-source=%s\n" "$source_path" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        'printf "install-source-content=%s\n" "$(cat "$source_path")" >>"${VEDETTA_TEST_UPDATE_LOG:?}"' \
        'exit 0' >"$UPDATE_BIN/install"
    printf '%s\n' '#!/usr/bin/env bash' 'printf "mv %s\n" "$*" >>"${VEDETTA_TEST_UPDATE_LOG:?}"; exit 0' >"$UPDATE_BIN/mv"
    chmod +x "$UPDATE_BIN"/*
    : >"$UPDATE_LOG"
}

run_update() {
    local expected="${1:-}" race_head="${2:-}" build_fail="${3:-}" compose_file="${4:-}"
    local compose_race="${5:-}" sensor_race="${6:-}"
    local writable_sensor_path="${7:-}"
    local writable_snapshot_suffix="${8:-}" writable_sensor_stage="${9:-}"
    local sensor_stage_mismatch="${10:-}"
    local test_uname="${11:-}" acl_path="${12:-}" test_error_path="${13:-}"
    local mode_mismatch_suffix="${14:-}" owner_mismatch_suffix="${15:-}"
    local pinned_port_fd=""
    [[ -n "$expected" ]] && pinned_port_fd=4
    set +e
    (
        cd "$UPDATE_WORK"
        PATH="$UPDATE_BIN:$PATH" \
        VEDETTA_EXPECTED_HEAD="$expected" \
        VEDETTA_PINNED_PORT_CONFIG_FD="$pinned_port_fd" \
        VEDETTA_TEST_UPDATE_LOG="$UPDATE_LOG" \
        VEDETTA_TEST_UPDATE_WORK="$UPDATE_WORK" \
        VEDETTA_TEST_UPDATE_RACE_HEAD="$race_head" \
        VEDETTA_TEST_DOCKER_BUILD_FAIL="$build_fail" \
        VEDETTA_TEST_COMPOSE_RACE="$compose_race" \
        VEDETTA_TEST_SENSOR_RACE="$sensor_race" \
        VEDETTA_TEST_WRITABLE_SENSOR_PATH="$writable_sensor_path" \
        VEDETTA_TEST_WRITABLE_SNAPSHOT_SUFFIX="$writable_snapshot_suffix" \
        VEDETTA_TEST_WRITABLE_SENSOR_STAGE="$writable_sensor_stage" \
        VEDETTA_TEST_SENSOR_STAGE_MISMATCH="$sensor_stage_mismatch" \
        VEDETTA_TEST_UNAME="$test_uname" \
        VEDETTA_TEST_ACL_PATH="$acl_path" \
        VEDETTA_TEST_TEST_ERROR_PATH="$test_error_path" \
        VEDETTA_TEST_MODE_MISMATCH_SUFFIX="$mode_mismatch_suffix" \
        VEDETTA_TEST_OWNER_MISMATCH_SUFFIX="$owner_mismatch_suffix" \
        VEDETTA_TEST_REAL_GIT="$REAL_GIT" \
        COMPOSE_FILE="$compose_file" \
        USER="${USER:-$(id -un)}" \
        bash "$UPDATE_WORK/scripts/update-all.sh" \
            4<"$UPDATE_WORK/scripts/lib/port-config.sh"
    ) >"$UPDATE_OUTPUT" 2>&1
    UPDATE_RC=$?
    set -e
}

setup_update_case pinned-no-pull
printf '%s\n' runtime >"$UPDATE_WORK/runtime.ignored"
printf '%s\n' 'services: {backend: {build: /unreviewed/override}}' >"$UPDATE_WORK/docker-compose.override.yml"
MALICIOUS_COMPOSE="$UPDATE_DIR/malicious-compose.yml"
printf '%s\n' 'services: {backend: {build: /unreviewed/environment}}' >"$MALICIOUS_COMPOSE"
mkdir -p "$UPDATE_WORK/backend" "$UPDATE_WORK/telemetry" \
    "$UPDATE_WORK/frontend/node_modules/example" \
    "$UPDATE_WORK/frontend/dist"
printf '%s\n' binary >"$UPDATE_WORK/backend/vedetta"
printf '%s\n' binary >"$UPDATE_WORK/telemetry/telemetry"
printf '%s\n' module >"$UPDATE_WORK/frontend/node_modules/example/index.js"
printf '%s\n' built >"$UPDATE_WORK/frontend/dist/index.html"
printf '%s\n' runtime >"$UPDATE_WORK/frontend/.env.placeholder"
run_update "$UPDATE_A" "" "" "$MALICIOUS_COMPOSE"
is "$UPDATE_RC" "0" "pinned update succeeds while upstream has advanced"
is "$(git -C "$UPDATE_WORK" rev-parse HEAD)" "$UPDATE_A" "pinned update never moves to newer remote commit"
ok not_grep 'git pull' "$UPDATE_LOG" "pinned update performs no git pull"
ok not_grep 'go mod tidy' "$UPDATE_LOG" "pinned update performs no source-updating tidy"
ok grep -Eq 'sudo -u root go build -buildvcs=false -o /(private/)?var/tmp/vedetta-pinned\.[^ ]+/output/vedetta-sensor ./cmd/vedetta-sensor' "$UPDATE_LOG" "pinned sensor build uses a protected output and cannot execute mutable Git metadata through VCS stamping"
UPDATE_WORK_PHYSICAL="$(CDPATH= cd -- "$UPDATE_WORK" && pwd -P)"
PINNED_COMPOSE_PATTERN="docker compose -f /(private/)?var/tmp/vedetta-pinned\\.[^ ]+/source/docker-compose.yml -f /(private/)?var/tmp/vedetta-pinned\\.[^ ]+/build-contexts.yml --project-directory $UPDATE_WORK_PHYSICAL"
ok grep -Eq "$PINNED_COMPOSE_PATTERN build --no-cache backend frontend collector telemetry" "$UPDATE_LOG" "pinned update explicitly builds every default Compose service from the protected reviewed snapshot"
ok grep -Eq "$PINNED_COMPOSE_PATTERN up -d --no-build backend frontend collector telemetry" "$UPDATE_LOG" "pinned update starts only reviewed default-service images without implicit builds"
ok not_grep "$UPDATE_WORK_PHYSICAL/docker-compose.yml" "$UPDATE_LOG" "pinned Compose never reads its base graph from the mutable checkout"
ok not_grep "$MALICIOUS_COMPOSE" "$UPDATE_LOG" "COMPOSE_FILE cannot replace pinned deployment graph"
ok not_grep 'docker-compose.override.yml' "$UPDATE_LOG" "ignored Compose override cannot replace pinned deployment graph"
ok grep -Eq 'sudo -u root chmod -R go-w /(private/)?var/tmp/vedetta-pinned\.[^ ]+/source' "$UPDATE_LOG" "production snapshot protection preserves reviewed owner mode bits while removing non-owner writes"
ok not_grep 'sudo -u root chmod -R a-w' "$UPDATE_LOG" "production snapshot protection does not rewrite tracked 0644/0755 modes to 0444/0555"
ok grep -Fq 'chmod -RN "$PINNED_BUILD_ROOT"' "$UPDATE_SCRIPT" "macOS snapshot hardening strips inherited ACLs before verification"
ok grep -Fq 'chmod -N "$SENSOR_INSTALL_TMP"' "$UPDATE_SCRIPT" "macOS sensor staging strips inherited ACLs before rename"
initial_acl_line="$(grep -nF 'chmod -N "$PINNED_BUILD_ROOT"' "$UPDATE_SCRIPT" | head -1 | cut -d: -f1)"
snapshot_mkdir_line="$(grep -nF 'mkdir -p -- "$PINNED_SOURCE_DIR"' "$UPDATE_SCRIPT" | head -1 | cut -d: -f1)"
recursive_acl_line="$(grep -nF 'chmod -RN "$PINNED_BUILD_ROOT"' "$UPDATE_SCRIPT" | head -1 | cut -d: -f1)"
final_chown_line="$(grep -nF 'chown -R 0:0 "$PINNED_BUILD_ROOT"' "$UPDATE_SCRIPT" | head -1 | cut -d: -f1)"
ok test "$initial_acl_line" -lt "$snapshot_mkdir_line" "empty snapshot root loses inherited macOS ACLs before extraction"
ok test "$recursive_acl_line" -lt "$final_chown_line" "recursive ACL stripping precedes final snapshot ownership hardening"
ok grep -Eq 'install-source=/(private/)?var/tmp/vedetta-pinned\.[^ ]+/output/vedetta-sensor' "$UPDATE_LOG" "pinned sensor installation reads only the protected build artifact"
ok grep -Fq 'sudo -u root mktemp /usr/local/bin/vedetta-sensor.tmp.XXXXXX' "$UPDATE_LOG" "pinned sensor stages in the privileged destination directory"
ok grep -Fq 'mv -f -- /usr/local/bin/vedetta-sensor.tmp.TEST /usr/local/bin/vedetta-sensor' "$UPDATE_LOG" "pinned sensor installation ends with an atomic same-directory rename"
ok not_grep "install-source=$UPDATE_WORK_PHYSICAL/sensor/vedetta-sensor" "$UPDATE_LOG" "pinned sensor install never consumes a mutable-worktree artifact"
ok test -e "$UPDATE_WORK/runtime.ignored" "pinned update permits deliberately ignored runtime state"
ok test -e "$UPDATE_WORK/backend/vedetta" "pinned update permits reviewed ignored build artifacts"

setup_update_case writable-sensor-ancestor
run_update "$UPDATE_A" "" "" "" "" "" "/usr/local"
ok test "$UPDATE_RC" -ne 0 "pinned update rejects a deployment-user-writable sensor destination ancestor"
ok grep -Fq 'Pinned sensor destination is writable by the deployment account: /usr/local' "$UPDATE_OUTPUT" "writable sensor ancestor has an explicit physical-path diagnostic"
ok not_grep 'docker ' "$UPDATE_LOG" "writable sensor ancestor fails before any Compose side effect"
ok not_grep 'go build' "$UPDATE_LOG" "writable sensor ancestor performs no sensor build"
ok not_grep 'install ' "$UPDATE_LOG" "writable sensor ancestor performs no privileged sensor install"
ok not_grep 'systemctl restart' "$UPDATE_LOG" "writable sensor ancestor performs no sensor restart"

setup_update_case granular-darwin-destination-acl
run_update "$UPDATE_A" "" "" "" "" "" "" "" "" "" "Darwin" "/usr/local/bin"
ok test "$UPDATE_RC" -ne 0 "pinned update rejects granular macOS ACL authority on the destination"
ok grep -Fq 'Pinned sensor destination may not contain an extended ACL: /usr/local/bin' "$UPDATE_OUTPUT" "granular destination ACL has an explicit diagnostic"
ok not_grep 'docker ' "$UPDATE_LOG" "destination ACL fails before any Compose side effect"

setup_update_case destination-write-probe-error
run_update "$UPDATE_A" "" "" "" "" "" "" "" "" "" "" "" "/usr/local"
ok test "$UPDATE_RC" -ne 0 "pinned update fails closed when effective-write probing errors"
ok grep -Fq 'Pinned sensor destination is writable by the deployment account: /usr/local' "$UPDATE_OUTPUT" "write-probe error has a fail-closed destination diagnostic"
ok not_grep 'docker ' "$UPDATE_LOG" "write-probe error fails before any Compose side effect"

setup_update_case snapshot-mode-mismatch
run_update "$UPDATE_A" "" "" "" "" "" "" "" "" "" "" "" "" "/source/backend/.tracked"
ok test "$UPDATE_RC" -ne 0 "pinned update rejects a protected snapshot mode mismatch"
ok grep -Fq 'Pinned build snapshot has an ownership or exact-mode mismatch:' "$UPDATE_OUTPUT" "snapshot mode mismatch has an explicit diagnostic"
ok not_grep 'docker ' "$UPDATE_LOG" "snapshot mode mismatch fails before any Compose side effect"

setup_update_case snapshot-owner-mismatch
run_update "$UPDATE_A" "" "" "" "" "" "" "" "" "" "" "" "" "" "/source/backend/.tracked"
ok test "$UPDATE_RC" -ne 0 "pinned update rejects a protected snapshot owner mismatch"
ok grep -Fq 'Pinned build snapshot remains writable by the deployment account.' "$UPDATE_OUTPUT" "snapshot owner mismatch has an explicit diagnostic"
ok not_grep 'docker ' "$UPDATE_LOG" "snapshot owner mismatch fails before any Compose side effect"

setup_update_case inherited-snapshot-acl
run_update "$UPDATE_A" "" "" "" "" "" "" "/source/backend/.tracked"
ok test "$UPDATE_RC" -ne 0 "pinned update rejects an inherited ACL that reopens a snapshot child"
ok grep -Fq 'Pinned build snapshot remains writable by the deployment account.' "$UPDATE_OUTPUT" "writable snapshot ACL has an explicit diagnostic"
ok not_grep 'docker ' "$UPDATE_LOG" "writable snapshot ACL fails before any Compose side effect"
ok not_grep 'go build' "$UPDATE_LOG" "writable snapshot ACL performs no sensor build"
ok not_grep 'install ' "$UPDATE_LOG" "writable snapshot ACL performs no sensor install"
ok not_grep 'systemctl restart' "$UPDATE_LOG" "writable snapshot ACL performs no sensor restart"

setup_update_case inherited-sensor-stage-acl
run_update "$UPDATE_A" "" "" "" "" "" "" "" "/usr/local/bin/vedetta-sensor.tmp.TEST"
ok test "$UPDATE_RC" -ne 0 "pinned update rejects an inherited ACL on the staged sensor binary"
ok grep -Fq 'Pinned sensor staging file remains writable by the deployment account.' "$UPDATE_OUTPUT" "writable staged sensor ACL has an explicit diagnostic"
ok grep -Fq 'install-source=' "$UPDATE_LOG" "staged sensor ACL regression reaches the protected install boundary"
ok not_grep 'mv -f -- /usr/local/bin/vedetta-sensor.tmp.TEST' "$UPDATE_LOG" "writable staged sensor is never renamed into place"
ok not_grep 'systemctl restart' "$UPDATE_LOG" "writable staged sensor ACL performs no sensor restart"

setup_update_case mutated-sensor-stage
run_update "$UPDATE_A" "" "" "" "" "" "" "" "" "1"
ok test "$UPDATE_RC" -ne 0 "pinned update rejects sensor staging bytes changed before ACL removal"
ok grep -Fq 'Pinned sensor staging bytes differ from the protected build artifact.' "$UPDATE_OUTPUT" "mutated staged sensor has an explicit integrity diagnostic"
ok grep -Fq 'cmp -s ' "$UPDATE_LOG" "sensor staging integrity is compared after permission hardening"
ok not_grep 'mv -f -- /usr/local/bin/vedetta-sensor.tmp.TEST' "$UPDATE_LOG" "mutated staged sensor is never renamed into place"
ok not_grep 'systemctl restart' "$UPDATE_LOG" "mutated staged sensor performs no sensor restart"

setup_update_case normal-pull
run_update ""
is "$UPDATE_RC" "0" "standalone non-pinned update behavior still succeeds"
is "$(git -C "$UPDATE_WORK" rev-parse HEAD)" "$UPDATE_B" "standalone update still pulls the configured branch"
ok grep -Fq 'git pull --rebase' "$UPDATE_LOG" "standalone update retains git pull --rebase"
ok grep -Fq 'go mod tidy' "$UPDATE_LOG" "standalone update retains go mod tidy"
ok grep -Fq 'go build -o vedetta-sensor ./cmd/vedetta-sensor' "$UPDATE_LOG" "standalone sensor build retains normal VCS behavior"
ok grep -Fq 'docker compose down' "$UPDATE_LOG" "standalone update retains normal Compose override discovery"
ok not_grep 'docker compose -f ' "$UPDATE_LOG" "standalone update does not force the pinned Compose graph"

setup_update_case compose-mutate-restore
run_update "$UPDATE_A" "" "" "" "1"
is "$UPDATE_RC" "0" "tracked Compose inputs can mutate and restore during a pinned Docker build without affecting deployed bytes"
is "$(cat "$UPDATE_WORK/backend/.tracked")" "tracked" "Compose race restores the mutable worktree source before post-build verification"
is "$(cat "$UPDATE_WORK/docker-compose.yml")" "services: {}" "Compose race restores the mutable worktree graph before post-build verification"
ok grep -Fq 'docker-build-source=tracked' "$UPDATE_LOG" "Docker build reads the reviewed snapshot while the worktree source is malicious"
ok grep -Fq 'docker-build-compose=services: {}' "$UPDATE_LOG" "Docker build reads the reviewed snapshot Compose graph while the worktree graph is malicious"
ok grep -Fq 'docker-build-snapshot=read-only' "$UPDATE_LOG" "Docker build snapshot is non-writable by the deployment user"
ok grep -Fq 'docker-build-context-count=5' "$UPDATE_LOG" "all Compose build contexts point into the same protected snapshot"
ok not_grep '/malicious/worktree' "$UPDATE_LOG" "mutate-and-restore Compose graph never reaches the Docker build"

setup_update_case sensor-mutate-restore
run_update "$UPDATE_A" "" "" "" "" "1"
is "$UPDATE_RC" "0" "tracked sensor inputs can mutate and restore during a pinned Go build without affecting the installed artifact"
is "$(cat "$UPDATE_WORK/sensor/go.mod")" "module example.invalid/pinned-update-test" "sensor race restores the mutable worktree input before post-build verification"
is "$(cat "$UPDATE_WORK/sensor/vedetta-sensor")" "malicious-worktree-binary" "sensor race plants a replacement worktree artifact for the install test"
ok grep -Fq 'sensor-build-source=module example.invalid/pinned-update-test' "$UPDATE_LOG" "Go build reads the reviewed snapshot while the worktree source is malicious"
ok grep -Fq 'sensor-build-snapshot=read-only' "$UPDATE_LOG" "Go build source snapshot is non-writable by the deployment user"
ok grep -Eq 'install-source=/(private/)?var/tmp/vedetta-pinned\.[^ ]+/output/vedetta-sensor' "$UPDATE_LOG" "sensor installer reads the protected artifact after a worktree replacement attempt"
ok grep -Fq 'install-source-content=sensor-built-from:module example.invalid/pinned-update-test' "$UPDATE_LOG" "installed sensor bytes came from the reviewed snapshot"
ok not_grep 'install-source-content=malicious-worktree-binary' "$UPDATE_LOG" "replacement worktree binary never reaches the privileged install"
ok grep -Fq 'mv -f -- /usr/local/bin/vedetta-sensor.tmp.TEST /usr/local/bin/vedetta-sensor' "$UPDATE_LOG" "sensor race still finishes through the atomic privileged rename"

setup_update_case moved-during-update
run_update "$UPDATE_A" "$UPDATE_B"
ok test "$UPDATE_RC" -ne 0 "pinned update rejects checkout movement at side-effect boundary"
ok grep -Fq ' down' "$UPDATE_LOG" "race occurs after initial exact-head verification"
ok not_grep 'docker compose build' "$UPDATE_LOG" "moved checkout is rejected before any build"
ok not_grep 'systemctl restart' "$UPDATE_LOG" "moved checkout is rejected before service restart"
ok grep -Fq 'Pinned update expected' "$UPDATE_OUTPUT" "moved checkout reports exact-head mismatch"

setup_update_case replacement-object
printf '%s\n' malicious >"$UPDATE_WORK/README.md"
git -C "$UPDATE_WORK" add README.md
REPLACEMENT_TREE="$(git -C "$UPDATE_WORK" write-tree)"
REPLACEMENT_COMMIT="$(printf '%s\n' replacement | git -C "$UPDATE_WORK" commit-tree "$REPLACEMENT_TREE" -p "$UPDATE_A")"
git -C "$UPDATE_WORK" reset -q --hard "$UPDATE_A"
git -C "$UPDATE_WORK" update-ref "refs/replace/$UPDATE_A" "$REPLACEMENT_COMMIT"
git -C "$UPDATE_WORK" reset -q --hard "$UPDATE_A"
is "$(cat "$UPDATE_WORK/README.md")" "malicious" "replacement object materializes an unreviewed tree under the expected HEAD"
ok git -C "$UPDATE_WORK" diff --quiet -- "ordinary Git considers the replacement-backed worktree clean"
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects a replacement-backed worktree"
ok not_grep 'docker ' "$UPDATE_LOG" "replacement-backed worktree performs no Docker action"
ok grep -Eq 'tracked bytes that differ from the reviewed index|index differs from the reviewed commit' "$UPDATE_OUTPUT" "replacement-object failure is explicit"

setup_update_case command-bearing-config
EXECUTOR="$UPDATE_DIR/executor.sh"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf git-config >"${VEDETTA_TEST_UNREVIEWED_MARKER:?}"' \
    'exit 99' >"$EXECUTOR"
chmod +x "$EXECUTOR"
git -C "$UPDATE_WORK" config --local core.askPass "$EXECUTOR"
git -C "$UPDATE_WORK" config --local core.alternateRefsCommand "$EXECUTOR"
git -C "$UPDATE_WORK" config --local gc.recentObjectsHook "$EXECUTOR"
git -C "$UPDATE_WORK" config --local gpg.program "$EXECUTOR"
git -C "$UPDATE_WORK" config --local remote.origin.promisor true
git -C "$UPDATE_WORK" config --local remote.origin.uploadpack "$EXECUTOR"
VEDETTA_TEST_UNREVIEWED_MARKER="$UPDATE_DIR/unreviewed.marker"
export VEDETTA_TEST_UNREVIEWED_MARKER
run_update "$UPDATE_A"
unset VEDETTA_TEST_UNREVIEWED_MARKER
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects command-bearing Git configuration"
ok not_grep 'docker ' "$UPDATE_LOG" "command-bearing Git configuration performs no Docker action"
ok test ! -e "$UPDATE_DIR/unreviewed.marker" "pinned metadata validation runs no configured program"
ok grep -Fq 'command-bearing or alternate-object Git configuration' "$UPDATE_OUTPUT" "pinned command-bearing configuration has an explicit diagnostic"

setup_update_case custom-protocol-config
git -C "$UPDATE_WORK" config --local protocol.foo.allow always
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects repository-local custom protocol permission"
ok not_grep 'docker ' "$UPDATE_LOG" "custom protocol permission performs no Docker action"
ok grep -Fq 'command-bearing or alternate-object Git configuration' "$UPDATE_OUTPUT" "pinned custom protocol permission has an explicit diagnostic"

setup_update_case alternate-object-store
printf '%s\n' "$UPDATE_BARE/objects" >"$UPDATE_WORK/.git/objects/info/alternates"
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects alternate object storage"
ok not_grep 'docker ' "$UPDATE_LOG" "alternate object storage performs no Docker action"
ok grep -Fq 'redirected Git metadata or object graphs' "$UPDATE_OUTPUT" "pinned alternate object storage has an explicit diagnostic"

setup_update_case hidden-index
git -C "$UPDATE_WORK" update-index --assume-unchanged README.md
printf '%s\n' hidden-pinned-change >"$UPDATE_WORK/README.md"
ok git -C "$UPDATE_WORK" diff --quiet -- "assume-unchanged masks a modified pinned-update file from ordinary diff"
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects hidden index state before side effects"
ok not_grep 'docker ' "$UPDATE_LOG" "hidden pinned-update state performs no Docker action"
ok not_grep 'systemctl restart' "$UPDATE_LOG" "hidden pinned-update state performs no service restart"
ok grep -Fq 'skip-worktree/assume-unchanged index flags' "$UPDATE_OUTPUT" "hidden pinned-update state has an explicit diagnostic"

setup_update_case untracked-source
mkdir -p "$UPDATE_WORK/sensor/cmd/vedetta-sensor"
printf '%s\n' 'package main' >"$UPDATE_WORK/sensor/cmd/vedetta-sensor/injected.go"
ok git -C "$UPDATE_WORK" diff --quiet -- "ordinary tracked diff ignores an untracked pinned-update source file"
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects untracked source before side effects"
ok not_grep 'docker ' "$UPDATE_LOG" "untracked pinned-update source performs no Docker action"
ok not_grep 'systemctl restart' "$UPDATE_LOG" "untracked pinned-update source performs no service restart"
ok grep -Fq 'untracked, non-ignored files' "$UPDATE_OUTPUT" "untracked pinned-update source has an explicit diagnostic"

setup_update_case ignored-source
mkdir -p "$UPDATE_WORK/sensor/cmd/vedetta-sensor"
printf '%s\n' 'package main' >"$UPDATE_WORK/sensor/cmd/vedetta-sensor/secret_inject.go"
ok git -C "$UPDATE_WORK" check-ignore -q sensor/cmd/vedetta-sensor/secret_inject.go "broad secret rule hides a shipped sensor source file"
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects ignored sensor source before side effects"
ok not_grep 'docker ' "$UPDATE_LOG" "ignored pinned-update source performs no Docker action"
ok grep -Fq 'ignored build input' "$UPDATE_OUTPUT" "ignored pinned-update source has an explicit diagnostic"

setup_update_case ignored-vendor
mkdir -p "$UPDATE_WORK/sensor/vendor"
ok git -C "$UPDATE_WORK" check-ignore -q sensor/vendor/ "vendor rule hides an empty Go vendor directory"
ok test -z "$(git -C "$UPDATE_WORK" ls-files --others --ignored --exclude-standard -- sensor/vendor)" "file-only ignored scan misses empty pinned-update vendor directory"
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects an empty ignored vendor directory before side effects"
ok not_grep 'docker ' "$UPDATE_LOG" "empty ignored vendor directory performs no Docker action"
ok grep -Fq 'ignored build directory' "$UPDATE_OUTPUT" "empty ignored vendor directory has an explicit diagnostic"

setup_update_case ignored-telemetry-source
mkdir -p "$UPDATE_WORK/telemetry/cmd/telemetry"
printf '%s\n' 'package main' >"$UPDATE_WORK/telemetry/cmd/telemetry/secret_inject.go"
ok git -C "$UPDATE_WORK" check-ignore -q telemetry/cmd/telemetry/secret_inject.go "broad secret rule hides a shipped telemetry source file"
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects ignored telemetry source before side effects"
ok not_grep 'docker ' "$UPDATE_LOG" "ignored telemetry source performs no Docker action"

setup_update_case ignored-collector-input
mkdir -p "$UPDATE_WORK/collector/config"
printf '%s\n' '[PARSER]' >"$UPDATE_WORK/collector/config/secret_parser.conf"
ok git -C "$UPDATE_WORK" check-ignore -q collector/config/secret_parser.conf "broad secret rule hides a collector build-context file"
run_update "$UPDATE_A"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects ignored collector input before side effects"
ok not_grep 'docker ' "$UPDATE_LOG" "ignored collector input performs no Docker action"

setup_update_case pinned-build-failure
run_update "$UPDATE_A" "" "1"
ok test "$UPDATE_RC" -ne 0 "reviewed Docker build failure makes pinned deployment fail"
ok not_grep 'up -d --no-build' "$UPDATE_LOG" "pinned build failure never starts stale images"
ok not_grep 'go build' "$UPDATE_LOG" "pinned build failure skips sensor build"
ok not_grep 'systemctl restart' "$UPDATE_LOG" "pinned build failure skips sensor restart"
ok grep -Fq 'refusing to start stale images' "$UPDATE_OUTPUT" "pinned build failure reports its fail-closed recovery boundary"
ok not_grep 'Update complete.' "$UPDATE_OUTPUT" "pinned build failure never claims update completion"

setup_update_case unpinned-build-failure
run_update "" "" "1"
is "$UPDATE_RC" "0" "standalone Docker build failure retains recovery behavior"
ok grep -Fq 'up -d --no-build backend frontend collector telemetry' "$UPDATE_LOG" "standalone build failure restores previous default-service containers"
ok grep -Fq 'WARNING: Running on stale images.' "$UPDATE_OUTPUT" "standalone build failure labels its recovery state"

setup_update_case invalid-expected-length
INVALID_EXPECTED="$(printf 'a%.0s' {1..41})"
run_update "$INVALID_EXPECTED"
ok test "$UPDATE_RC" -ne 0 "pinned updater rejects a 41-character pseudo-OID"
ok not_grep 'docker ' "$UPDATE_LOG" "invalid expected OID performs no Docker action"
ok grep -Fq 'complete Git commit object ID' "$UPDATE_OUTPUT" "invalid expected OID has an explicit diagnostic"

printf '1..%d\n' "$tests"
if ((failures)); then
    exit 1
fi
