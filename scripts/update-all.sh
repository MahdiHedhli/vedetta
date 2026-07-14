#!/usr/bin/env bash
#
# Vedetta — Update Everything (Core + Sensor)
#
# Usage:
#   sudo ./scripts/update-all.sh
#
# Pulls latest code, rebuilds Docker images, restarts Core services,
# rebuilds the sensor binary, and restarts the sensor service.
#
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)"
PROJECT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
REAL_USER="${SUDO_USER:-$USER}"
DEPLOY_SOURCE_DIR="$PROJECT_DIR"
PLIST_SRC="$DEPLOY_SOURCE_DIR/sensor/deploy/com.vedetta.sensor.plist"
PLIST_DEST="/Library/LaunchDaemons/com.vedetta.sensor.plist"
SERVICE_ID="system/com.vedetta.sensor"
SENSOR_BIN="/usr/local/bin/vedetta-sensor"
EXPECTED_HEAD="${VEDETTA_EXPECTED_HEAD:-}"
PINNED_PORT_CONFIG_FD="${VEDETTA_PINNED_PORT_CONFIG_FD:-}"
GIT_BIN="$(command -v git)"
PINNED_BUILD_ROOT=""
PINNED_SOURCE_DIR=""
PINNED_COMPOSE_OVERRIDE=""
PINNED_SENSOR_ARTIFACT=""
SENSOR_INSTALL_TMP=""

if [[ -n "$EXPECTED_HEAD" && ! "$EXPECTED_HEAD" =~ ^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$ ]]; then
    echo "VEDETTA_EXPECTED_HEAD must be a complete Git commit object ID." >&2
    exit 2
fi
if [[ -n "$EXPECTED_HEAD" && ( ! -d "$PROJECT_DIR/.git" || -L "$PROJECT_DIR/.git" ) ]]; then
    echo "Pinned update requires a canonical, non-linked .git directory." >&2
    exit 2
fi

# Read ports as Docker Compose will: exported shell values first, then practical
# dotenv syntax, then the `:-` defaults in docker-compose.yml. Never source .env;
# it contains secrets and is configuration data, not shell code. Pinned deploys
# receive this helper from the reviewed Git object on a dedicated descriptor;
# sourcing the worktree before exact verification would re-open a between-session
# code-execution race.
# shellcheck source=scripts/lib/port-config.sh
if [[ -n "$EXPECTED_HEAD" ]]; then
    if [[ ! "$PINNED_PORT_CONFIG_FD" =~ ^[3-9][0-9]*$ ||
          ! -r "/dev/fd/$PINNED_PORT_CONFIG_FD" ]]; then
        echo "Pinned update requires the reviewed port configuration helper." >&2
        exit 2
    fi
    # shellcheck source=/dev/null
    source "/dev/fd/$PINNED_PORT_CONFIG_FD"
else
    source "$SCRIPT_DIR/lib/port-config.sh"
fi
BACKEND_PORT="$(vedetta_resolve_port VEDETTA_BACKEND_PORT 8080 "$PROJECT_DIR/.env")"
FRONTEND_PORT="$(vedetta_resolve_port VEDETTA_FRONTEND_PORT 3107 "$PROJECT_DIR/.env")"
LOCAL_CORE_URL="http://localhost:${BACKEND_PORT}"
SENSOR_CORE_URL="${VEDETTA_CORE_URL:-${LOCAL_CORE_URL}}"
LOG_FILE="/usr/local/var/log/vedetta-sensor.log"
MAX_RETRIES=3
VERIFY_WAIT=5
DEFAULT_SERVICES=(backend frontend collector telemetry)

pinned_git() {
    sudo -u "$REAL_USER" env \
        -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_COMMON_DIR \
        -u GIT_OBJECT_DIRECTORY -u GIT_ALTERNATE_OBJECT_DIRECTORIES \
        -u GIT_ATTR_SOURCE -u GIT_CONFIG -u GIT_CONFIG_COUNT \
        -u GIT_CONFIG_PARAMETERS -u GIT_EXEC_PATH -u GIT_ALLOW_PROTOCOL \
        -u GIT_PROTOCOL_FROM_USER -u GIT_SHALLOW_FILE -u GIT_GRAFT_FILE \
        -u GIT_NAMESPACE -u GIT_QUARANTINE_PATH -u GIT_EXTERNAL_DIFF \
        -u GIT_DIFF_OPTS -u GIT_SSL_NO_VERIFY -u GIT_CURL_VERBOSE \
        -u GIT_SSH -u GIT_SSH_COMMAND -u GIT_SSH_VARIANT \
        -u GIT_PROXY_COMMAND -u GIT_ASKPASS -u SSH_ASKPASS \
        -u SSH_ASKPASS_REQUIRE \
        GIT_ATTR_NOSYSTEM=1 GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 \
        GIT_PROXY_COMMAND= GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false \
        SSH_ASKPASS_REQUIRE=never GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat \
        GIT_EDITOR=true GIT_SEQUENCE_EDITOR=true GIT_MERGE_AUTOEDIT=no \
        GIT_SSH_VARIANT=ssh \
        "$GIT_BIN" --no-replace-objects -C "$PROJECT_DIR" \
        --git-dir="$PROJECT_DIR/.git" --work-tree="$PROJECT_DIR" \
        -c core.hooksPath=/dev/null \
        -c core.fsmonitor=false \
        -c core.untrackedCache=false \
        -c core.fileMode=true \
        -c core.symlinks=true \
        -c core.attributesFile=/dev/null \
        -c core.excludesFile=/dev/null \
        -c "core.sshCommand=ssh -oBatchMode=yes" \
        -c core.gitProxy=none \
        -c core.askPass=/bin/false \
        -c credential.helper= \
        -c credential.interactive=false \
        -c maintenance.auto=false \
        -c gc.auto=0 \
        -c merge.verifySignatures=false \
        -c fetch.bundleURI= \
        -c promisor.acceptFromServer=none \
        -c protocol.allow=never \
        -c protocol.file.allow=always \
        -c protocol.git.allow=never \
        -c protocol.http.allow=always \
        -c protocol.https.allow=always \
        -c protocol.ssh.allow=always \
        -c protocol.ext.allow=never \
        "$@"
}

validate_pinned_git_metadata() {
    local git_dir="$PROJECT_DIR/.git" configured_keys key promisor_file
    if [[ ! -f "$git_dir/config" || -L "$git_dir/config" ||
          ! -f "$git_dir/HEAD" || -L "$git_dir/HEAD" ||
          ! -f "$git_dir/index" || -L "$git_dir/index" ||
          ! -d "$git_dir/objects" || -L "$git_dir/objects" ]]; then
        echo "Pinned update requires regular, local Git control files." >&2
        return 2
    fi
    if [[ -e "$git_dir/commondir" || -L "$git_dir/commondir" ||
          -e "$git_dir/config.worktree" || -L "$git_dir/config.worktree" ||
          -e "$git_dir/objects/info/alternates" || -L "$git_dir/objects/info/alternates" ||
          -e "$git_dir/info/grafts" || -L "$git_dir/info/grafts" ]]; then
        echo "Pinned update rejects redirected Git metadata or object graphs." >&2
        return 2
    fi
    if ! configured_keys="$(
        pinned_git config --local --includes --name-only --get-regexp '.*' |
            LC_ALL=C tr '[:upper:]' '[:lower:]'
    )"; then
        echo "Pinned update cannot inspect Git configuration safely." >&2
        return 2
    fi
    while IFS= read -r key; do
        case "$key" in
            filter.*|branch.*.mergeoptions|core.alternaterefscommand|\
            core.askpass|core.gitproxy|core.sshcommand|credential.helper|\
            credential.*.helper|extensions.partialclone|fetch.bundleuri|\
            gc.recentobjectshook|gpg.program|gpg.*.program|include.*|\
            includeif.*|merge.*.driver|merge.verifysignatures|\
            protocol.allow|protocol.*.allow|remote.*.partialclonefilter|\
            remote.*.promisor|remote.*.uploadpack|remote.*.vcs|\
            submodule.*.update|url.*.insteadof|\
            url.*.pushinsteadof)
                echo "Pinned update rejects command-bearing or alternate-object Git configuration." >&2
                return 2
                ;;
        esac
    done <<<"$configured_keys"
    for promisor_file in "$git_dir"/objects/pack/*.promisor; do
        if [[ -e "$promisor_file" || -L "$promisor_file" ]]; then
            echo "Pinned update does not support a partial/promisor object store." >&2
            return 2
        fi
    done
    return 0
}

verify_pinned_tracked_tree() {
    local verify_dir listing paths expected actual
    local entry metadata path mode oid stage failure=""
    verify_dir="$(mktemp -d "${TMPDIR:-/tmp}/vedetta-worktree.XXXXXX")" || return 2
    listing="$verify_dir/index"
    paths="$verify_dir/paths"
    expected="$verify_dir/expected"
    actual="$verify_dir/actual"
    : >"$paths"
    : >"$expected"
    if ! pinned_git ls-files --stage -z >"$listing"; then
        rm -rf -- "$verify_dir"
        echo "Pinned update cannot enumerate tracked files safely." >&2
        return 2
    fi
    while IFS= read -r -d '' entry; do
        metadata="${entry%%$'\t'*}"
        path="${entry#*$'\t'}"
        read -r mode oid stage <<<"$metadata"
        if [[ "$stage" != "0" || "$path" == *$'\n'* ]]; then
            failure="Pinned update found an unsupported index stage or filename."
            break
        fi
        case "$mode" in
            100644)
                if [[ ! -f "$PROJECT_DIR/$path" || -L "$PROJECT_DIR/$path" || -x "$PROJECT_DIR/$path" ]]; then
                    failure="Pinned update found a tracked file type or mode mismatch: $path ($mode)."
                fi
                ;;
            100755)
                if [[ ! -f "$PROJECT_DIR/$path" || -L "$PROJECT_DIR/$path" || ! -x "$PROJECT_DIR/$path" ]]; then
                    failure="Pinned update found a tracked file type or mode mismatch: $path ($mode)."
                fi
                ;;
            *)
                failure="Pinned update does not support tracked symlinks, gitlinks, or special modes."
                ;;
        esac
        [[ -z "$failure" ]] || break
        printf '%s\n' "$PROJECT_DIR/$path" >>"$paths"
        printf '%s\n' "$oid" >>"$expected"
    done <"$listing"
    if [[ -z "$failure" ]] &&
       ! pinned_git hash-object --no-filters --stdin-paths <"$paths" >"$actual"; then
        failure="Pinned update cannot hash tracked files without filters."
    fi
    if [[ -z "$failure" ]] && ! cmp -s "$expected" "$actual"; then
        failure="Pinned update found tracked bytes that differ from the reviewed index."
    fi
    if [[ -z "$failure" ]] &&
       ! pinned_git diff-index --cached --quiet --no-ext-diff "$EXPECTED_HEAD" --; then
        failure="Pinned update index differs from the reviewed commit."
    fi
    rm -rf -- "$verify_dir"
    if [[ -n "$failure" ]]; then
        echo "$failure" >&2
        return 2
    fi
    return 0
}

# deploy.sh supplies VEDETTA_EXPECTED_HEAD after publishing and remotely
# fast-forwarding one reviewed commit. In that mode, update-all must never pull,
# rebase, or otherwise move the checkout. Re-check before every meaningful
# build/deploy/restart boundary so concurrent local movement fails closed.
verify_expected_checkout() {
    [[ -n "$EXPECTED_HEAD" ]] || return 0

    local actual_head listing untracked ignored_build ignored_directories artifact entry tag
    validate_pinned_git_metadata || return 2
    actual_head="$(pinned_git rev-parse --verify HEAD^{commit})"
    if [[ "$actual_head" != "$EXPECTED_HEAD" ]]; then
        echo "Pinned update expected $EXPECTED_HEAD but checkout is $actual_head." >&2
        return 2
    fi
    if ! listing="$(pinned_git ls-files -v)"; then
        echo "Pinned update cannot inspect Git index flags safely." >&2
        return 2
    fi
    while IFS= read -r entry; do
        tag="${entry:0:1}"
        if [[ "$tag" == "S" || "$tag" =~ [a-z] ]]; then
            echo "Pinned update refuses skip-worktree/assume-unchanged index flags." >&2
            return 2
        fi
    done <<<"$listing"
    if ! untracked="$(pinned_git ls-files --others --exclude-per-directory=.gitignore)"; then
        echo "Pinned update cannot inspect untracked files safely." >&2
        return 2
    fi
    if [[ -n "$untracked" ]]; then
        echo "Pinned update refuses untracked, non-ignored files." >&2
        return 2
    fi
    for artifact in backend/vedetta sensor/vedetta-sensor telemetry/telemetry; do
        if [[ ( -e "$PROJECT_DIR/$artifact" || -L "$PROJECT_DIR/$artifact" ) &&
              ( ! -f "$PROJECT_DIR/$artifact" || -L "$PROJECT_DIR/$artifact" ) ]]; then
            echo "Pinned update found an unsupported ignored build artifact." >&2
            return 2
        fi
    done
    if ! ignored_build="$(pinned_git \
        ls-files --others --ignored --exclude-per-directory=.gitignore -- \
        backend frontend collector telemetry sensor siem/migrations \
        ':(exclude)backend/vedetta' \
        ':(exclude)sensor/vedetta-sensor' \
        ':(exclude)telemetry/telemetry' \
        ':(exclude,glob)frontend/node_modules/**' \
        ':(exclude,glob)frontend/dist/**' \
        ':(exclude)frontend/.env' \
        ':(exclude,glob)frontend/.env.*')"; then
        echo "Pinned update cannot inspect ignored build inputs safely." >&2
        return 2
    fi
    if [[ -n "$ignored_build" ]]; then
        echo "Pinned update refuses an ignored build input." >&2
        return 2
    fi
    if ! ignored_directories="$(pinned_git \
        ls-files --others --ignored --exclude-per-directory=.gitignore --directory -- \
        backend frontend collector telemetry sensor siem/migrations)"; then
        echo "Pinned update cannot inspect ignored build directories safely." >&2
        return 2
    fi
    while IFS= read -r entry; do
        case "$entry" in
            ""|backend/vedetta|sensor/vedetta-sensor|telemetry/telemetry|\
            frontend/node_modules|frontend/node_modules/|\
            frontend/dist|frontend/dist/|frontend/.env|frontend/.env.*)
                ;;
            *)
                echo "Pinned update refuses an ignored build directory." >&2
                return 2
                ;;
        esac
    done <<<"$ignored_directories"
    # Root .env and docker-compose.override.yml are deliberately external
    # deployment configuration. Ignored files inside build roots are restricted
    # above so they cannot silently alter Docker or Go build inputs.
    verify_pinned_tracked_tree || return 2
    return 0
}

cleanup_pinned_build() {
    local status=$?
    trap - EXIT HUP INT TERM

    if [[ -n "$SENSOR_INSTALL_TMP" ]]; then
        sudo -u root rm -f -- "$SENSOR_INSTALL_TMP" >/dev/null 2>&1 || true
    fi
    if [[ -n "$PINNED_BUILD_ROOT" ]]; then
        # Tests exercise this as an unprivileged owner, and it also makes cleanup
        # deterministic on platforms where rm will not traverse read-only dirs.
        sudo -u root chmod -R u+w "$PINNED_BUILD_ROOT" >/dev/null 2>&1 || true
        sudo -u root rm -rf -- "$PINNED_BUILD_ROOT" >/dev/null 2>&1 || true
    fi
    exit "$status"
}

verify_pinned_snapshot() {
    local verify_dir listing paths dirs expected actual expected_paths actual_paths
    local entry metadata path mode type oid failure="" actual_mode owner gid expected_mode
    verify_dir="$(mktemp -d "${TMPDIR:-/tmp}/vedetta-snapshot-verify.XXXXXX")" || return 2
    listing="$verify_dir/tree"
    paths="$verify_dir/paths"
    dirs="$verify_dir/dirs"
    expected="$verify_dir/expected"
    actual="$verify_dir/actual"
    expected_paths="$verify_dir/expected-paths"
    actual_paths="$verify_dir/actual-paths"
    : >"$paths"
    : >"$expected"
    : >"$expected_paths"

    if ! pinned_git ls-tree -r -z --full-tree "$EXPECTED_HEAD" >"$listing"; then
        failure="Pinned update cannot enumerate the reviewed tree for its build snapshot."
    fi
    if [[ -z "$failure" ]]; then
        while IFS= read -r -d '' entry; do
            metadata="${entry%%$'\t'*}"
            path="${entry#*$'\t'}"
            read -r mode type oid <<<"$metadata"
            if [[ "$type" != "blob" || "$path" == *$'\n'* ]]; then
                failure="Pinned update found an unsupported object or filename in the reviewed tree."
                break
            fi
            case "$mode" in
                100644)
                    expected_mode=644
                    ;;
                100755)
                    expected_mode=755
                    ;;
                *)
                    failure="Pinned build snapshot does not support symlinks, gitlinks, or special modes."
                    ;;
            esac
            [[ -z "$failure" ]] || break
            if [[ ! -f "$PINNED_SOURCE_DIR/$path" || -L "$PINNED_SOURCE_DIR/$path" ]] ||
               ! actual_mode="$(path_mode "$PINNED_SOURCE_DIR/$path")" ||
               ! owner="$(path_owner_uid "$PINNED_SOURCE_DIR/$path")" ||
               ! gid="$(path_group_gid "$PINNED_SOURCE_DIR/$path")" ||
               [[ "$actual_mode" != "$expected_mode" || "$owner" != "0" || "$gid" != "0" ]]; then
                failure="Pinned build snapshot has an ownership or exact-mode mismatch: $path ($mode)."
                break
            fi
            printf '%s\n' "$PINNED_SOURCE_DIR/$path" >>"$paths"
            printf '%s\n' "$oid" >>"$expected"
            printf '%s\n' "$path" >>"$expected_paths"
        done <"$listing"
    fi
    if [[ -z "$failure" ]] &&
       ! sudo -u root find "$PINNED_SOURCE_DIR" -type d -print0 >"$dirs"; then
        failure="Pinned update cannot enumerate protected snapshot directories."
    fi
    if [[ -z "$failure" ]] &&
       ! while IFS= read -r -d '' path; do
            owner="$(path_owner_uid "$path")" || exit 1
            gid="$(path_group_gid "$path")" || exit 1
            actual_mode="$(path_mode "$path")" || exit 1
            [[ "$owner" == "0" && "$gid" == "0" && "$actual_mode" == "755" ]] || exit 1
          done <"$dirs"; then
        failure="Pinned build snapshot directory ownership or mode differs from the protected layout."
    fi
    if [[ -z "$failure" ]] &&
       [[ -n "$(find "$PINNED_SOURCE_DIR" -mindepth 1 ! -type f ! -type d -print -quit)" ]]; then
        failure="Pinned build snapshot contains an unsupported filesystem object."
    fi
    if [[ -z "$failure" ]] &&
       ! (
            cd "$PINNED_SOURCE_DIR"
            while IFS= read -r -d '' path; do
                path="${path#./}"
                [[ "$path" != *$'\n'* ]] || exit 1
                printf '%s\n' "$path"
            done < <(find . -type f -print0)
        ) | LC_ALL=C sort >"$actual_paths"; then
        failure="Pinned build snapshot contains an unsupported filename."
    fi
    if [[ -z "$failure" ]]; then
        LC_ALL=C sort "$expected_paths" >"$expected_paths.sorted"
        if ! cmp -s "$expected_paths.sorted" "$actual_paths"; then
            failure="Pinned build snapshot file set differs from the reviewed commit."
        fi
    fi
    if [[ -z "$failure" ]] &&
       ! pinned_git hash-object --no-filters --stdin-paths <"$paths" >"$actual"; then
        failure="Pinned update cannot hash its protected build snapshot."
    fi
    if [[ -z "$failure" ]] && ! cmp -s "$expected" "$actual"; then
        failure="Pinned build snapshot bytes differ from the reviewed commit."
    fi
    rm -rf -- "$verify_dir"
    if [[ -n "$failure" ]]; then
        echo "$failure" >&2
        return 2
    fi
    return 0
}

prepare_pinned_build_root() {
    local requested_parent="/var/tmp" physical_parent path owner gid mode real_uid
    if ! physical_parent="$(sudo -u root bash -c \
        'cd -P -- "$1" && pwd -P' bash "$requested_parent")"; then
        echo "Pinned update cannot resolve its protected snapshot parent." >&2
        return 2
    fi
    real_uid="$(deployment_user_uid)" || return 2
    path="$physical_parent"
    while true; do
        owner="$(path_owner_uid "$path")" || return 2
        gid="$(path_group_gid "$path")" || return 2
        if [[ "$owner" != "0" || "$gid" != "0" ]]; then
            echo "Pinned snapshot parent requires a root-owned physical chain: $path" >&2
            return 2
        fi
        verify_no_darwin_acl "$path" "Pinned snapshot parent" || return 2
        if [[ "$path" == "$physical_parent" ]]; then
            mode="$(path_mode "$path")" || return 2
            # /var/tmp is intentionally shared. A root-owned sticky parent
            # prevents another user from renaming the root-owned mktemp child.
            if (( (8#$mode & 01000) == 0 )); then
                if [[ "$real_uid" != "0" ]] &&
                   ! sudo -u "$REAL_USER" test ! -w "$path"; then
                    echo "Pinned snapshot parent is neither sticky nor deployment-user protected." >&2
                    return 2
                fi
            fi
        elif [[ "$real_uid" != "0" ]] &&
             ! sudo -u "$REAL_USER" test ! -w "$path"; then
            echo "Pinned snapshot parent ancestor is writable by the deployment account: $path" >&2
            return 2
        fi
        [[ "$path" == "/" ]] && break
        path="${path%/*}"
        [[ -n "$path" ]] || path="/"
    done

    PINNED_BUILD_ROOT="$(sudo -u root mktemp -d "$physical_parent/vedetta-pinned.XXXXXX")" || return 2
    trap cleanup_pinned_build EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ "$(uname)" == "Darwin" ]]; then
        sudo -u root chmod -N "$PINNED_BUILD_ROOT"
    fi
    sudo -u root chown 0:0 "$PINNED_BUILD_ROOT"
    sudo -u root chmod 0700 "$PINNED_BUILD_ROOT"
    if [[ "$(path_owner_uid "$PINNED_BUILD_ROOT")" != "0" ||
          "$(path_group_gid "$PINNED_BUILD_ROOT")" != "0" ||
          "$(path_mode "$PINNED_BUILD_ROOT")" != "700" ]] ||
       ! verify_no_darwin_acl "$PINNED_BUILD_ROOT" "Pinned snapshot root" ||
       [[ -n "$(sudo -u root find "$PINNED_BUILD_ROOT" -mindepth 1 -print -quit)" ]] ||
       { [[ "$real_uid" != "0" ]] &&
         ! sudo -u "$REAL_USER" test ! -w "$PINNED_BUILD_ROOT"; }; then
        echo "Pinned update could not establish an empty protected snapshot root." >&2
        return 2
    fi
    return 0
}

materialize_pinned_build_snapshot() {
    [[ -n "$EXPECTED_HEAD" ]] || return 0
    local unsupported

    prepare_pinned_build_root || return 2
    PINNED_SOURCE_DIR="$PINNED_BUILD_ROOT/source"
    PINNED_COMPOSE_OVERRIDE="$PINNED_BUILD_ROOT/build-contexts.yml"
    PINNED_SENSOR_ARTIFACT="$PINNED_BUILD_ROOT/output/vedetta-sensor"
    sudo -u root mkdir -p -- "$PINNED_SOURCE_DIR" "$PINNED_BUILD_ROOT/output"
    if ! pinned_git archive --format=tar "$EXPECTED_HEAD" |
         sudo -u root tar -xf - -C "$PINNED_SOURCE_DIR"; then
        echo "Pinned update could not materialize the reviewed build snapshot." >&2
        return 2
    fi

    # Override every build context, including the non-default community service,
    # while retaining PROJECT_DIR as Compose's project directory. That preserves
    # the installation's .env interpolation, project name, volumes, and rollback
    # identity without allowing the mutable checkout to supply build bytes.
    printf '%s\n' \
        'services:' \
        '  backend:' \
        '    build:' \
        "      context: \"$PINNED_SOURCE_DIR\"" \
        '      dockerfile: "backend/Dockerfile"' \
        '  frontend:' \
        '    build:' \
        "      context: \"$PINNED_SOURCE_DIR/frontend\"" \
        '      dockerfile: "Dockerfile"' \
        '  collector:' \
        '    build:' \
        "      context: \"$PINNED_SOURCE_DIR/collector\"" \
        '      dockerfile: "Dockerfile"' \
        '  telemetry:' \
        '    build:' \
        "      context: \"$PINNED_SOURCE_DIR/telemetry\"" \
        '      dockerfile: "Dockerfile"' \
        '  threat-network:' \
        '    build:' \
        "      context: \"$PINNED_SOURCE_DIR/threat-network\"" \
        '      dockerfile: "Dockerfile"' |
        sudo -u root tee "$PINNED_COMPOSE_OVERRIDE" >/dev/null

    # git archive's tar headers are not an ownership boundary. Re-own everything
    # after extraction and remove group/other write access while preserving the
    # reviewed 0644/0755 modes used by Docker COPY. Keep sensor output root-only.
    if ! unsupported="$(sudo -u root find "$PINNED_SOURCE_DIR" -mindepth 1 \
        ! -type f ! -type d -print -quit)"; then
        echo "Pinned update cannot validate the extracted snapshot filesystem." >&2
        return 2
    fi
    if [[ -n "$unsupported" ]]; then
        echo "Pinned build snapshot contains an unsupported filesystem object." >&2
        return 2
    fi
    # BSD chmod preserves inherited ACL entries unless they are removed
    # explicitly. Strip them before the final recursive ownership/mode pass so
    # no inherited ACE can survive as a deployment-account-owned reviewed file.
    if [[ "$(uname)" == "Darwin" ]]; then
        sudo -u root chmod -RN "$PINNED_BUILD_ROOT"
    fi
    sudo -u root chown -R 0:0 "$PINNED_BUILD_ROOT"
    sudo -u root find "$PINNED_SOURCE_DIR" -type d -exec chmod 0755 {} +
    sudo -u root chmod -R go-w "$PINNED_SOURCE_DIR"
    sudo -u root chmod 0444 "$PINNED_COMPOSE_OVERRIDE"
    sudo -u root chmod 0700 "$PINNED_BUILD_ROOT/output"
    sudo -u root chmod 0755 "$PINNED_BUILD_ROOT"

    verify_deployment_account_cannot_write_tree "$PINNED_BUILD_ROOT"
    verify_pinned_snapshot
    DEPLOY_SOURCE_DIR="$PINNED_SOURCE_DIR"
    PLIST_SRC="$DEPLOY_SOURCE_DIR/sensor/deploy/com.vedetta.sensor.plist"
}

path_owner_uid() {
    local path="$1" owner
    if owner="$(sudo -u root stat -c '%u' "$path" 2>/dev/null)" &&
       [[ "$owner" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$owner"
        return 0
    fi
    if owner="$(sudo -u root stat -f '%u' "$path" 2>/dev/null)" &&
       [[ "$owner" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$owner"
        return 0
    fi
    return 1
}

path_group_gid() {
    local path="$1" gid
    if gid="$(sudo -u root stat -c '%g' "$path" 2>/dev/null)" &&
       [[ "$gid" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$gid"
        return 0
    fi
    if gid="$(sudo -u root stat -f '%g' "$path" 2>/dev/null)" &&
       [[ "$gid" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$gid"
        return 0
    fi
    return 1
}

path_mode() {
    local path="$1" mode
    if mode="$(sudo -u root stat -c '%a' "$path" 2>/dev/null)" &&
       [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
        printf '%s\n' "${mode#0}"
        return 0
    fi
    if mode="$(sudo -u root stat -f '%Lp' "$path" 2>/dev/null)" &&
       [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
        printf '%s\n' "${mode#0}"
        return 0
    fi
    return 1
}

verify_no_darwin_acl() {
    local path="$1" context="$2" listing
    [[ "$(uname)" == "Darwin" ]] || return 0
    if ! listing="$(sudo -u root env LC_ALL=C /bin/ls -lde -- "$path")"; then
        echo "$context ACL inspection failed: $path" >&2
        return 2
    fi
    if [[ "$listing" == *$'\n'* ]]; then
        echo "$context may not contain an extended ACL: $path" >&2
        return 2
    fi
    return 0
}

deployment_user_uid() {
    local real_uid
    if ! real_uid="$(id -u "$REAL_USER")" || [[ ! "$real_uid" =~ ^[0-9]+$ ]]; then
        echo "Pinned update cannot resolve the deployment account identity." >&2
        return 2
    fi
    printf '%s\n' "$real_uid"
}

verify_deployment_account_cannot_write_tree() {
    local protected_root="$1" real_uid
    real_uid="$(deployment_user_uid)" || return 2
    [[ "$real_uid" != "0" ]] || return 0

    if ! sudo -u root find "$protected_root" -print0 |
         (
             while IFS= read -r -d '' protected_path; do
                 [[ "$(path_owner_uid "$protected_path")" == "0" ]] || exit 1
                 [[ "$(path_group_gid "$protected_path")" == "0" ]] || exit 1
                 verify_no_darwin_acl "$protected_path" "Pinned build snapshot" || exit 1
                 # Negate inside `test`: writable paths and sudo/test errors
                 # both become a non-zero fail-closed result here.
                 if ! sudo -u "$REAL_USER" test ! -w "$protected_path"; then
                     exit 1
                 fi
             done
         ); then
        echo "Pinned build snapshot remains writable by the deployment account." >&2
        return 2
    fi
    return 0
}

verify_deployment_account_cannot_write_file() {
    local protected_file="$1" real_uid mode
    real_uid="$(deployment_user_uid)" || return 2
    if ! sudo -u root test -f "$protected_file" || sudo -u root test -L "$protected_file" ||
       [[ "$(path_owner_uid "$protected_file")" != "0" ||
          "$(path_group_gid "$protected_file")" != "0" ]] ||
       ! mode="$(path_mode "$protected_file")" || [[ "$mode" != "755" ]] ||
       ! verify_no_darwin_acl "$protected_file" "Pinned sensor staging file"; then
        echo "Pinned sensor staging file has unsafe ownership, mode, or ACL." >&2
        return 2
    fi
    if [[ "$real_uid" != "0" ]] &&
       ! sudo -u "$REAL_USER" test ! -w "$protected_file"; then
        echo "Pinned sensor staging file remains writable by the deployment account." >&2
        return 2
    fi
    return 0
}

validate_sensor_install_destination() {
    local requested_dir binary_name physical_dir path owner gid real_uid
    requested_dir="$(dirname -- "$SENSOR_BIN")"
    binary_name="$(basename -- "$SENSOR_BIN")"
    if [[ "$requested_dir" != /* || "$binary_name" == */* ]]; then
        echo "Pinned sensor destination must be an absolute filesystem path." >&2
        return 2
    fi
    if ! physical_dir="$(sudo -u root bash -c \
        'cd -P -- "$1" && pwd -P' bash "$requested_dir")"; then
        echo "Pinned sensor destination directory is unavailable." >&2
        return 2
    fi
    if [[ "$physical_dir" != "$requested_dir" ]]; then
        echo "Pinned sensor destination may not traverse symlinked directories." >&2
        return 2
    fi
    real_uid="$(deployment_user_uid)" || return 2

    path="$physical_dir"
    while true; do
        if ! owner="$(path_owner_uid "$path")" || [[ "$owner" != "0" ]] ||
           ! gid="$(path_group_gid "$path")" || [[ "$gid" != "0" ]]; then
            echo "Pinned sensor destination requires a root-owned directory chain: $path" >&2
            return 2
        fi
        if ! verify_no_darwin_acl "$path" "Pinned sensor destination"; then
            return 2
        fi
        # Effective access includes POSIX ACL grants. Root itself is the explicit
        # trusted boundary; for every other deployment account, any writable
        # directory in the physical chain permits rename/unlink replacement.
        if [[ "$real_uid" != "0" ]] &&
           ! sudo -u "$REAL_USER" test ! -w "$path"; then
            echo "Pinned sensor destination is writable by the deployment account: $path" >&2
            return 2
        fi
        [[ "$path" == "/" ]] && break
        path="${path%/*}"
        [[ -n "$path" ]] || path="/"
    done

    SENSOR_BIN="$physical_dir/$binary_name"
    if [[ -L "$SENSOR_BIN" || ( -e "$SENSOR_BIN" && ! -f "$SENSOR_BIN" ) ]]; then
        echo "Pinned sensor destination must be absent or a regular non-symlink file." >&2
        return 2
    fi
    return 0
}

run_compose() {
    if [[ -n "$EXPECTED_HEAD" ]]; then
        # Pin deployment topology as well as source. An ignored
        # docker-compose.override.yml or COMPOSE_FILE remains available to a
        # standalone operator update, but cannot replace reviewed build contexts
        # during deploy.sh's exact-commit path.
        if [[ -z "$PINNED_SOURCE_DIR" || -z "$PINNED_COMPOSE_OVERRIDE" ]]; then
            echo "Pinned update has no protected build snapshot." >&2
            return 2
        fi
        docker compose -f "$PINNED_SOURCE_DIR/docker-compose.yml" \
            -f "$PINNED_COMPOSE_OVERRIDE" \
            --project-directory "$PROJECT_DIR" "$@"
    else
        docker compose "$@"
    fi
}

# ─── Sensor management ────────────────────────────────────────

stop_sensor() {
    # Try service manager first
    if [[ "$(uname)" == "Darwin" ]]; then
        launchctl bootout "$SERVICE_ID" 2>/dev/null || true
    elif command -v systemctl &> /dev/null; then
        systemctl stop vedetta-sensor 2>/dev/null || true
    fi

    sleep 1

    # Force-kill if still running
    if pgrep -f vedetta-sensor > /dev/null 2>&1; then
        echo "  Sensor still running — sending SIGTERM..."
        pkill -f vedetta-sensor 2>/dev/null || true
        sleep 2
        if pgrep -f vedetta-sensor > /dev/null 2>&1; then
            echo "  Forcing shutdown (SIGKILL)..."
            pkill -9 -f vedetta-sensor 2>/dev/null || true
            sleep 1
        fi
    fi
}

install_sensor_service() {
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "  Installing launchd service..."

        # Ensure log directory exists
        mkdir -p "$(dirname "$LOG_FILE")"

        # Generate plist from template with correct core URL
        sed "s|http://CORE_IP:8080|${SENSOR_CORE_URL}|g" "$PLIST_SRC" > "$PLIST_DEST"
        chown root:wheel "$PLIST_DEST"
        chmod 644 "$PLIST_DEST"

        # Bootstrap the service
        launchctl bootout "$SERVICE_ID" 2>/dev/null || true
        sleep 1
        if launchctl bootstrap system "$PLIST_DEST"; then
            echo "  ✓ Sensor installed as launchd service (survives reboots)."
            return 0
        else
            echo "  ✗ launchd bootstrap failed."
            return 1
        fi
    elif command -v systemctl &> /dev/null; then
        echo "  Installing systemd service..."
        local unit_src="$DEPLOY_SOURCE_DIR/sensor/deploy/vedetta-sensor.service"
        if [[ -f "$unit_src" ]]; then
            cp "$unit_src" /etc/systemd/system/vedetta-sensor.service
            systemctl daemon-reload
            systemctl enable --now vedetta-sensor
            echo "  ✓ Sensor installed as systemd service (survives reboots)."
            return 0
        else
            echo "  ✗ No systemd unit file found at $unit_src"
            return 1
        fi
    fi
    return 1
}

start_sensor_once() {
    echo "  Launching sensor (this session only)..."
    mkdir -p "$(dirname "$LOG_FILE")"
    nohup "$SENSOR_BIN" --core "$SENSOR_CORE_URL" >> "$LOG_FILE" 2>&1 &
    local pid=$!
    echo "  ✓ Sensor launched (PID $pid)"
    echo "  Logs: $LOG_FILE"
}

prompt_sensor_start() {
    echo ""
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │  How would you like to start the sensor? │"
    echo "  ├─────────────────────────────────────────┤"
    echo "  │  1) Launch now (stops on reboot)        │"
    echo "  │  2) Install as service (survives reboot)│"
    echo "  │  3) Skip — I'll start it manually       │"
    echo "  └─────────────────────────────────────────┘"
    echo ""

    local choice
    while true; do
        read -rp "  Select [1/2/3] (default: 2): " choice
        choice="${choice:-2}"
        case "$choice" in
            1)
                start_sensor_once
                return
                ;;
            2)
                if install_sensor_service; then
                    return
                else
                    echo ""
                    echo "  Service installation failed. Falling back to direct launch..."
                    start_sensor_once
                    return
                fi
                ;;
            3)
                echo "  Skipped. To start manually:"
                echo "    sudo $SENSOR_BIN --core $SENSOR_CORE_URL"
                return
                ;;
            *)
                echo "  Please enter 1, 2, or 3."
                ;;
        esac
    done
}

restart_sensor() {
    echo "▸ Restarting sensor..."
    stop_sensor

    if [[ "$(uname)" == "Darwin" ]]; then
        restart_sensor_launchd
    elif command -v systemctl &> /dev/null; then
        restart_sensor_systemd
    else
        echo "  No service manager detected."
        prompt_sensor_start
        verify_sensor
        return
    fi

    verify_sensor
}

restart_sensor_launchd() {
    # No plist installed — ask what the user wants to do
    if [[ ! -f "$PLIST_DEST" ]]; then
        echo "  No sensor service is currently installed."
        prompt_sensor_start
        return
    fi

    # Plist exists — try to restart via launchd
    for attempt in $(seq 1 $MAX_RETRIES); do
        echo "  launchd bootstrap attempt $attempt/$MAX_RETRIES..."
        if launchctl bootstrap system "$PLIST_DEST" 2>/dev/null; then
            echo "  ✓ launchd bootstrap succeeded."
            return
        fi

        echo "  Bootstrap failed — unloading and retrying..."
        launchctl bootout "$SERVICE_ID" 2>/dev/null || true
        sleep 1
    done

    # All retries exhausted — ask the user
    echo ""
    echo "  launchd failed after $MAX_RETRIES attempts."
    prompt_sensor_start
}

restart_sensor_systemd() {
    if ! systemctl is-enabled vedetta-sensor &> /dev/null; then
        echo "  No sensor service is currently installed."
        prompt_sensor_start
        return
    fi

    for attempt in $(seq 1 $MAX_RETRIES); do
        echo "  systemd restart attempt $attempt/$MAX_RETRIES..."
        if systemctl restart vedetta-sensor 2>/dev/null; then
            sleep 1
            if systemctl is-active --quiet vedetta-sensor; then
                echo "  ✓ systemd restart succeeded."
                return
            fi
        fi
        sleep 2
    done

    echo ""
    echo "  systemd failed after $MAX_RETRIES attempts."
    prompt_sensor_start
}

verify_sensor() {
    echo ""
    echo "▸ Verifying sensor is running..."
    sleep "$VERIFY_WAIT"
    if pgrep -f vedetta-sensor > /dev/null 2>&1; then
        local pid
        pid=$(pgrep -f vedetta-sensor | head -1)
        echo "  ✓ Sensor running (PID $pid)"
    else
        echo "  ✗ Sensor does not appear to be running."
        echo ""
        echo "  This can happen if the sensor exited immediately on startup."
        echo "  Check logs: $LOG_FILE"
        echo "  Manual start: sudo $SENSOR_BIN --core $SENSOR_CORE_URL"
    fi
}

# ─── Main ──────────────────────────────────────────────────────

echo "═══════════════════════════════════════════"
echo "  Vedetta — Full Update"
echo "═══════════════════════════════════════════"
echo ""

# --- Select source revision ---
cd "$PROJECT_DIR"
if [[ -n "$EXPECTED_HEAD" ]]; then
    echo "▸ Using reviewed commit $EXPECTED_HEAD (network update disabled)..."
    verify_expected_checkout
    validate_sensor_install_destination
    materialize_pinned_build_snapshot
else
    echo "▸ Pulling latest from git..."
    sudo -u "$REAL_USER" git pull --rebase
fi
echo ""

# --- Update Core ---
echo "▸ Rebuilding Core Docker images..."
verify_expected_checkout
run_compose down
verify_expected_checkout

if ! run_compose build --no-cache "${DEFAULT_SERVICES[@]}"; then
    verify_expected_checkout
    echo ""
    echo "  ✗ Docker build FAILED — NOT starting the previous images."
    echo ""
    echo "    Starting the old images now would run old code against whatever"
    echo "    image tags a partial multi-service build may already have replaced."
    echo "    The stack is left stopped and your database is untouched."
    echo ""
    echo "    Fix the build error, then upgrade the trustworthy way — it snapshots"
    echo "    the DB first, verifies integrity, and auto-rolls-back on failure:"
    echo "        ./scripts/upgrade.sh"
    echo ""
    echo "    (Or, once the build is fixed: docker compose build --no-cache && docker compose up -d)"
    echo ""
    exit 1
fi
verify_expected_checkout
echo "  ✓ Docker build succeeded."
run_compose up -d --no-build "${DEFAULT_SERVICES[@]}"
echo ""

# Wait for backend READINESS, not mere liveness. /readyz returns 200 only once
# migrations have applied, the schema head matches this build, and the DB passes its
# integrity/foreign-key check — so this loop waits through the migration window and
# won't declare a half-migrated or broken upgrade "ready". (60s comfortably exceeds
# the compose start_period; /readyz 503s until Core is genuinely ready.)
echo "▸ Waiting for backend to become ready (/readyz)..."
for i in $(seq 1 60); do
    if curl -sf --connect-timeout 1 --max-time 5 "${LOCAL_CORE_URL}/readyz" > /dev/null 2>&1; then
        echo "  Backend ready."
        # Verify new routes are present
        ROUTE_CHECK=$(curl -sf "${LOCAL_CORE_URL}/api/v1/version" 2>/dev/null)
        if echo "$ROUTE_CHECK" | grep -q "suppression" 2>/dev/null; then
            echo "  ✓ New API routes verified."
        else
            echo "  ⚠ Backend is running but may be an older build (missing /api/v1/version)."
            echo "    Try: docker compose down && docker compose build --no-cache backend && docker compose up -d"
        fi
        break
    fi
    if [ "$i" -eq 60 ]; then
        # A timed-out readiness wait is a FAILED update — do NOT proceed to rebuild and
        # restart the sensor against a Core that is mid-migration or serving a broken DB.
        echo "  ERROR: Backend did not become ready within 60s."
        echo "  Diagnose: docker logs vedetta-backend  and  curl ${LOCAL_CORE_URL}/readyz"
        exit 1
    fi
    sleep 1
done
echo ""

# --- Update Sensor ---
echo "▸ Rebuilding sensor..."
verify_expected_checkout
if [[ -z "$EXPECTED_HEAD" ]]; then
    cd "$PROJECT_DIR/sensor"
    sudo -u "$REAL_USER" go mod tidy
else
    cd "$PINNED_SOURCE_DIR/sensor"
    echo "  Pinned update: skipping go mod tidy (source mutation disabled)."
fi
verify_expected_checkout
if [[ -n "$EXPECTED_HEAD" ]]; then
    # Go's default VCS stamping invokes repository Git and can therefore execute
    # mutable fsmonitor/filter configuration after our hardened verifier. The
    # reviewed commit is already pinned explicitly, so omit redundant VCS probes.
    sudo -u root go build -buildvcs=false -o "$PINNED_SENSOR_ARTIFACT" ./cmd/vedetta-sensor
    if [[ ! -f "$PINNED_SENSOR_ARTIFACT" || -L "$PINNED_SENSOR_ARTIFACT" ]]; then
        echo "Pinned sensor build did not produce a protected regular-file artifact." >&2
        exit 2
    fi
    sudo -u root chmod 0555 "$PINNED_SENSOR_ARTIFACT"
else
    sudo -u "$REAL_USER" go build -o vedetta-sensor ./cmd/vedetta-sensor
fi
verify_expected_checkout
if [[ -n "$EXPECTED_HEAD" ]]; then
    # Stage in the privileged destination directory so the final rename is
    # atomic and no REAL_USER-writable path exists between build and install.
    validate_sensor_install_destination
    SENSOR_INSTALL_TMP="$(sudo -u root mktemp "${SENSOR_BIN}.tmp.XXXXXX")"
    sudo -u root install -m 0755 -- "$PINNED_SENSOR_ARTIFACT" "$SENSOR_INSTALL_TMP"
    if [[ "$(uname)" == "Darwin" ]]; then
        sudo -u root chmod -N "$SENSOR_INSTALL_TMP"
    fi
    sudo -u root chown 0:0 "$SENSOR_INSTALL_TMP"
    sudo -u root chmod 0755 "$SENSOR_INSTALL_TMP"
    verify_deployment_account_cannot_write_file "$SENSOR_INSTALL_TMP"
    if ! sudo -u root cmp -s "$PINNED_SENSOR_ARTIFACT" "$SENSOR_INSTALL_TMP"; then
        echo "Pinned sensor staging bytes differ from the protected build artifact." >&2
        exit 2
    fi
    validate_sensor_install_destination
    sudo -u root mv -f -- "$SENSOR_INSTALL_TMP" "$SENSOR_BIN"
    SENSOR_INSTALL_TMP=""
    verify_deployment_account_cannot_write_file "$SENSOR_BIN"
    if ! sudo -u root cmp -s "$PINNED_SENSOR_ARTIFACT" "$SENSOR_BIN"; then
        echo "Pinned installed sensor bytes differ from the protected build artifact." >&2
        exit 2
    fi
else
    cp vedetta-sensor "$SENSOR_BIN"
fi
echo "  Binary installed to $SENSOR_BIN"
echo ""

# --- Restart with resilience ---
verify_expected_checkout
restart_sensor

echo ""
echo "═══════════════════════════════════════════"
echo "  Update complete."
echo "  Dashboard: http://localhost:${FRONTEND_PORT}"
echo "  API:       http://localhost:${BACKEND_PORT}/api/v1/status (read/admin bearer required)"
echo "═══════════════════════════════════════════"
