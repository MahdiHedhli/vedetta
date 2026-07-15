#!/bin/bash
# deploy.sh — Publish one reviewed commit, then fast-forward Core to that exact SHA.
# Usage: ./scripts/deploy.sh [commit message]
#
# Prerequisites:
#   - SSH key access to the deployment host
#   - VEDETTA_DEPLOY_HOST and VEDETTA_REMOTE_DIR environment variables

set -euo pipefail
export GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1

DEPLOY_HOST="${VEDETTA_DEPLOY_HOST:?Set VEDETTA_DEPLOY_HOST to the SSH host or alias}"
REMOTE_DIR="${VEDETTA_REMOTE_DIR:?Set VEDETTA_REMOTE_DIR to the remote repository path}"
VEDETTA_DIR="$(git rev-parse --show-toplevel)"

if [[ ! "$DEPLOY_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9._@:-]*$ ]]; then
    echo "VEDETTA_DEPLOY_HOST contains unsupported characters" >&2
    exit 2
fi
if [[ ! "$REMOTE_DIR" =~ ^/[A-Za-z0-9._/\ -]+$ ]]; then
    echo "VEDETTA_REMOTE_DIR must be an absolute path without shell metacharacters" >&2
    exit 2
fi

cd "$VEDETTA_DIR"

reject_hidden_index_flags() {
    local listing entry tag
    if ! listing="$(git ls-files -v)"; then
        echo "Cannot inspect Git index flags safely." >&2
        return 2
    fi
    while IFS= read -r entry; do
        tag="${entry:0:1}"
        if [[ "$tag" == "S" || "$tag" =~ [a-z] ]]; then
            echo "Deployment refuses skip-worktree/assume-unchanged index flags." >&2
            return 2
        fi
    done <<<"$listing"
    return 0
}

reject_hidden_index_flags

echo "==> Checking for changes..."
if [[ -n $(git status --porcelain) ]]; then
    git add -A
    # This pre-commit check gives the operator immediate feedback. The immutable
    # committed tree is checked again below, so a moving index cannot be pushed.
    bash scripts/check-repo-sanitization.sh
    if [[ -n "${1:-}" ]]; then
        git commit -m "$1"
    else
        echo "Uncommitted changes found but no commit message provided." >&2
        echo "Usage: ./scripts/deploy.sh \"your commit message\"" >&2
        exit 1
    fi
fi

current_branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
if [[ -z "$current_branch" ]]; then
    echo "Deployment requires a named local branch; detached HEAD is not supported." >&2
    exit 2
fi
if [[ ! "$current_branch" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]; then
    echo "The current branch contains unsupported deployment characters." >&2
    exit 2
fi

# URL selection, rewrite inspection, and transport must see the same Git
# configuration. In particular, GIT_CONFIG affects `git config` differently
# from ordinary Git commands and could otherwise blind rewrite inspection while
# leaving transport rewrites active. Ignore that config-command-only override
# for this publication boundary while retaining the repository, user, system,
# and command-scope configuration shared by ordinary Git commands.
publish_config_git() {
    env -u GIT_CONFIG git "$@"
}

# Resolve the actual push remote from Git configuration. Parsing an abbreviated
# upstream at '/' is incorrect because slash is valid in a remote name.
push_remote="$(publish_config_git config --get "branch.$current_branch.pushRemote" || true)"
if [[ -z "$push_remote" ]]; then
    push_remote="$(publish_config_git config --get remote.pushDefault || true)"
fi
if [[ -z "$push_remote" ]]; then
    push_remote="$(publish_config_git config --get "branch.$current_branch.remote" || true)"
fi
if [[ -z "$push_remote" ]] && publish_config_git remote get-url origin >/dev/null 2>&1; then
    push_remote="origin"
fi
if [[ -z "$push_remote" || "$push_remote" == "." ]]; then
    echo "Cannot determine a non-local Git push remote for deployment." >&2
    exit 2
fi
if [[ ! "$push_remote" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] ||
   ! publish_config_git remote get-url "$push_remote" >/dev/null 2>&1; then
    echo "The configured deployment remote is unsupported or does not exist." >&2
    exit 2
fi

# A remote may fetch from one repository but publish to a distinct pushurl.
# Observe, fetch, lease, and push the single captured push destination itself;
# otherwise history from a read mirror could be mistaken for published history.
push_url="$(publish_config_git remote get-url --push --all "$push_remote")"
if [[ -z "$push_url" || "$push_url" == *$'\n'* || "$push_url" == -* ]]; then
    echo "Deployment requires exactly one supported push URL." >&2
    exit 2
fi
case "$push_url" in
    /*|file:///*|http://?*|https://?*|ssh://?*)
        ;;
    *)
        # Unknown URI schemes and the transport::address syntax invoke a
        # git-remote-* helper. Only an ordinary scp-style host:path fallback is
        # supported here.
        if [[ "$push_url" == *://* || "$push_url" == *::* ||
              ! "$push_url" =~ ^([A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+:.+ ]]; then
            echo "Deployment push URL must be an explicit supported URL or absolute path." >&2
            exit 2
        fi
        ;;
esac
if publish_config_git remote get-url "$push_url" >/dev/null 2>&1; then
    echo "Deployment push URL ambiguously names another configured remote." >&2
    exit 2
fi

# `git remote get-url` expands at most one configured URL alias. Git can apply a
# second insteadOf/pushInsteadOf rule when the resulting URL is later used for
# transport. Reject any rule whose prefix can still match the frozen URL: that
# prevents both an allowed-name helper such as ssh::address and a push-only
# rewrite that would split inspection/fetch from publication. Ordinary one-step
# aliases remain supported because their original prefix no longer matches the
# captured result.
reject_reapplicable_url_rewrites() {
    local candidate_url="$1" rewrite_keys config_status key rewrite_prefix saw_value

    if rewrite_keys="$(
        publish_config_git config --includes --name-only --get-regexp \
            '^url\..*\.(insteadof|pushinsteadof)$'
    )"; then
        :
    else
        config_status=$?
        if [[ "$config_status" -eq 1 ]]; then
            return 0
        fi
        echo "Deployment cannot inspect configured Git URL rewrites safely." >&2
        return 2
    fi

    while IFS= read -r key; do
        if [[ ! "$key" =~ ^url\..+\.(insteadof|pushinsteadof)$ ]]; then
            echo "Deployment encountered an invalid Git URL rewrite key." >&2
            return 2
        fi
        saw_value=false
        while IFS= read -r -d '' rewrite_prefix; do
            saw_value=true
            if [[ -z "$rewrite_prefix" || "$candidate_url" == "$rewrite_prefix"* ]]; then
                echo "Deployment push URL remains subject to another configured Git URL rewrite." >&2
                return 2
            fi
        done < <(publish_config_git config --includes --null --get-all "$key")
        if [[ "$saw_value" != true ]]; then
            echo "Deployment Git URL rewrite configuration changed during inspection." >&2
            return 2
        fi
    done <<<"$rewrite_keys"
}

# Keep the native transports restricted at execution time too. Unset ambient
# helper-path, SSH-command, askpass, proxy-command, and protocol-origin
# overrides so a syntactically valid native URL cannot select an
# attacker-supplied transport program. Resolve an external ssh executable with
# the Bash builtin so an exported shell function cannot replace it. Its
# conservative absolute-path form is safe to pass through GIT_SSH_COMMAND's
# shell parsing, while normal ~/.ssh/config, keys, agent, and aliases still work.
ssh_bin="$(builtin type -P ssh 2>/dev/null || true)"
if [[ ! "$ssh_bin" =~ ^/[A-Za-z0-9._/+:-]+$ || ! -f "$ssh_bin" || ! -x "$ssh_bin" ]]; then
    echo "Deployment requires ssh at a safe absolute executable path." >&2
    exit 2
fi
publish_ssh_command="$ssh_bin -oBatchMode=yes"

publish_transport_git() {
    reject_reapplicable_url_rewrites "$push_url" || return $?
    env -u GIT_CONFIG -u GIT_EXEC_PATH -u GIT_PROTOCOL_FROM_USER \
        -u GIT_SSH -u GIT_SSH_COMMAND -u GIT_SSH_VARIANT \
        -u GIT_PROXY_COMMAND -u GIT_ASKPASS -u SSH_ASKPASS \
        -u SSH_ASKPASS_REQUIRE -u GIT_SSL_NO_VERIFY \
        GIT_ALLOW_PROTOCOL=file:http:https:ssh \
        GIT_SSH_COMMAND="$publish_ssh_command" GIT_SSH_VARIANT=ssh \
        GIT_PROXY_COMMAND= GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false \
        SSH_ASKPASS_REQUIRE=never GIT_TERMINAL_PROMPT=0 git "$@"
}

scanned_head="$(git rev-parse --verify HEAD^{commit})"
if ! git diff --quiet "$scanned_head" -- || ! git diff --cached --quiet "$scanned_head" --; then
    echo "Tracked worktree/index changed after the deployment commit; refusing to continue." >&2
    exit 2
fi
reject_hidden_index_flags

remote_ref="refs/heads/$current_branch"
temporary_ref="refs/vedetta-deploy/$$"
cleanup() {
    git update-ref -d "$temporary_ref" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Read and fetch the exact destination tip. The fetch closes the stale
# remote-tracking-ref bypass; the expected-tip lease below closes the race after
# this fetch. If ls-remote observed a branch and the fetch loses that race, fail
# closed rather than treating it as a new branch.
remote_listing="$(publish_transport_git ls-remote --heads "$push_url" "$remote_ref")"
expected_remote_tip=""
if [[ -n "$remote_listing" ]]; then
    if [[ "$remote_listing" == *$'\n'* ]]; then
        echo "The destination branch resolved to more than one remote ref." >&2
        exit 2
    fi
    observed_remote_tip="${remote_listing%%[[:space:]]*}"
    observed_remote_ref="${remote_listing#*[[:space:]]}"
    if [[ ! "$observed_remote_tip" =~ ^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$ ||
          "$observed_remote_ref" != "$remote_ref" ]]; then
        echo "The destination branch returned an invalid remote reference." >&2
        exit 2
    fi
    publish_transport_git fetch --no-tags "$push_url" "+$remote_ref:$temporary_ref"
    fetched_remote_tip="$(git rev-parse --verify "$temporary_ref^{commit}")"
    if [[ "$fetched_remote_tip" != "$observed_remote_tip" ]]; then
        echo "The destination branch moved between inspection and fetch; retry deployment." >&2
        exit 2
    fi
    expected_remote_tip="$observed_remote_tip"
    if ! git merge-base --is-ancestor "$expected_remote_tip" "$scanned_head"; then
        echo "The remote branch is not an ancestor of the reviewed commit; refusing a rewrite." >&2
        exit 2
    fi
    history_base="$expected_remote_tip"
else
    # A new branch is anchored to a freshly fetched main, not a possibly stale
    # local origin/main. An absent expected OID is also enforced by the lease.
    base_ref="refs/heads/${VEDETTA_DEPLOY_BASE_BRANCH:-main}"
    if [[ ! "$base_ref" =~ ^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]; then
        echo "VEDETTA_DEPLOY_BASE_BRANCH contains unsupported characters." >&2
        exit 2
    fi
    publish_transport_git fetch --no-tags "$push_url" "+$base_ref:$temporary_ref"
    trusted_base="$(git rev-parse --verify "$temporary_ref^{commit}")"
    history_base="$(git merge-base "$trusted_base" "$scanned_head" 2>/dev/null || true)"
    if [[ -z "$history_base" ]]; then
        # No shared reviewed history: inspect every tree reachable from the tip.
        history_base=""
    fi
fi

echo "==> Scanning immutable commit $scanned_head..."
scan_args=(--history-range "$scanned_head^!")
if [[ -n "$history_base" && "$history_base" != "$scanned_head" ]]; then
    scan_args+=(--history-range "$history_base..$scanned_head")
elif [[ -z "$history_base" ]]; then
    scan_args+=(--history-range "$scanned_head")
fi
bash scripts/check-repo-sanitization.sh "${scan_args[@]}"

# Check again after scanning. A concurrent local commit may move HEAD, but the
# exact scanned SHA remains the only object named by the push.
if ! git diff --quiet "$scanned_head" -- || ! git diff --cached --quiet "$scanned_head" --; then
    echo "Tracked worktree/index changed during sanitation; refusing to continue." >&2
    exit 2
fi
reject_hidden_index_flags

echo "==> Publishing exact reviewed commit to $push_remote/$current_branch..."
lease="--force-with-lease=$remote_ref:$expected_remote_tip"
publish_transport_git push --no-follow-tags "$lease" "$push_url" "$scanned_head:$remote_ref"

# OpenSSH transmits a remote command as one shell string, not an argv vector.
# Quote each already-validated value as a POSIX single-quoted argument so Bash
# receives the intended positional arguments even when REMOTE_DIR has spaces.
quote_remote_arg() {
    local value
    value="$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
    printf "'%s'" "$value"
}
remote_command="bash -s -- $(quote_remote_arg "$REMOTE_DIR") $(quote_remote_arg "$current_branch") $(quote_remote_arg "$scanned_head")"

echo "==> Updating deployment host ($DEPLOY_HOST) to $scanned_head..."
"$ssh_bin" "$DEPLOY_HOST" "$remote_command" <<'REMOTE_SCRIPT'
set -euo pipefail

remote_dir="$1"
expected_branch="$2"
expected_head="$3"

cd -- "$remote_dir"
remote_dir="$(pwd -P)"
git_dir="$remote_dir/.git"
if [[ ! -d "$git_dir" || -L "$git_dir" ]]; then
    echo "Remote deployment requires a canonical, non-linked .git directory." >&2
    exit 2
fi
git_bin="$(command -v git)"
git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_COMMON_DIR \
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
        "$git_bin" --no-replace-objects -C "$remote_dir" \
        --git-dir="$git_dir" --work-tree="$remote_dir" \
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
reject_unsafe_git_metadata() {
    local configured_keys key promisor_file
    if [[ ! -f "$git_dir/config" || -L "$git_dir/config" ||
          ! -f "$git_dir/HEAD" || -L "$git_dir/HEAD" ||
          ! -f "$git_dir/index" || -L "$git_dir/index" ||
          ! -d "$git_dir/objects" || -L "$git_dir/objects" ]]; then
        echo "Remote deployment requires regular, local Git control files." >&2
        return 2
    fi
    if [[ -e "$git_dir/commondir" || -L "$git_dir/commondir" ||
          -e "$git_dir/config.worktree" || -L "$git_dir/config.worktree" ||
          -e "$git_dir/objects/info/alternates" || -L "$git_dir/objects/info/alternates" ||
          -e "$git_dir/info/grafts" || -L "$git_dir/info/grafts" ]]; then
        echo "Remote Git metadata redirects the reviewed repository or object graph." >&2
        return 2
    fi
    if ! configured_keys="$(
        git config --local --includes --name-only --get-regexp '.*' |
            LC_ALL=C tr '[:upper:]' '[:lower:]'
    )"; then
        echo "Remote Git configuration cannot be inspected safely." >&2
        return 2
    fi
    while IFS= read -r key; do
        case "$key" in
            filter.*)
                echo "Remote Git metadata configures an unreviewed clean/smudge filter." >&2
                return 2
                ;;
            branch.*.mergeoptions|core.alternaterefscommand|core.askpass|\
            core.gitproxy|core.sshcommand|credential.helper|credential.*.helper|\
            extensions.partialclone|fetch.bundleuri|gc.recentobjectshook|\
            gpg.program|gpg.*.program|include.*|includeif.*|merge.*.driver|\
            merge.verifysignatures|protocol.allow|protocol.*.allow|\
            remote.*.partialclonefilter|remote.*.promisor|remote.*.uploadpack|\
            remote.*.vcs|submodule.*.update|\
            url.*.insteadof|url.*.pushinsteadof)
                echo "Remote Git metadata configures an unsupported external executor or object source." >&2
                return 2
                ;;
        esac
    done <<<"$configured_keys"
    for promisor_file in "$git_dir"/objects/pack/*.promisor; do
        if [[ -e "$promisor_file" || -L "$promisor_file" ]]; then
            echo "Remote deployment does not support a partial/promisor object store." >&2
            return 2
        fi
    done
    return 0
}
reject_unsafe_git_metadata
reported_root="$(git rev-parse --show-toplevel)"
if [[ "$(CDPATH= cd -- "$reported_root" && pwd -P)" != "$remote_dir" ]]; then
    echo "Remote Git metadata redirects the deployment worktree." >&2
    exit 2
fi
verify_tracked_tree() {
    local expected_commit="$1" verify_dir listing paths expected actual
    local entry metadata path mode oid stage failure=""
    verify_dir="$(mktemp -d "${TMPDIR:-/tmp}/vedetta-worktree.XXXXXX")" || return 2
    listing="$verify_dir/index"
    paths="$verify_dir/paths"
    expected="$verify_dir/expected"
    actual="$verify_dir/actual"
    : >"$paths"
    : >"$expected"
    if ! git ls-files --stage -z >"$listing"; then
        rm -rf -- "$verify_dir"
        echo "Cannot enumerate the remote tracked tree safely." >&2
        return 2
    fi
    while IFS= read -r -d '' entry; do
        metadata="${entry%%$'\t'*}"
        path="${entry#*$'\t'}"
        read -r mode oid stage <<<"$metadata"
        if [[ "$stage" != "0" || "$path" == *$'\n'* ]]; then
            failure="Remote index contains an unsupported stage or filename."
            break
        fi
        case "$mode" in
            100644)
                if [[ ! -f "$remote_dir/$path" || -L "$remote_dir/$path" || -x "$remote_dir/$path" ]]; then
                    failure="Remote tracked file type or mode differs from the reviewed index."
                fi
                ;;
            100755)
                if [[ ! -f "$remote_dir/$path" || -L "$remote_dir/$path" || ! -x "$remote_dir/$path" ]]; then
                    failure="Remote tracked file type or mode differs from the reviewed index."
                fi
                ;;
            *)
                failure="Remote deployment does not support tracked symlinks, gitlinks, or special modes."
                ;;
        esac
        [[ -z "$failure" ]] || break
        printf '%s\n' "$remote_dir/$path" >>"$paths"
        printf '%s\n' "$oid" >>"$expected"
    done <"$listing"
    if [[ -z "$failure" ]] &&
       ! git hash-object --no-filters --stdin-paths <"$paths" >"$actual"; then
        failure="Cannot hash the remote tracked tree without filters."
    fi
    if [[ -z "$failure" ]] && ! cmp -s "$expected" "$actual"; then
        failure="Remote tracked file bytes differ from the reviewed index."
    fi
    if [[ -z "$failure" ]] &&
       ! git diff-index --cached --quiet --no-ext-diff "$expected_commit" --; then
        failure="Remote index differs from the reviewed commit."
    fi
    rm -rf -- "$verify_dir"
    if [[ -n "$failure" ]]; then
        echo "$failure" >&2
        return 2
    fi
    return 0
}
reject_hidden_index_flags() {
    local listing entry tag
    if ! listing="$(git ls-files -v)"; then
        echo "Cannot inspect remote Git index flags safely." >&2
        return 2
    fi
    while IFS= read -r entry; do
        tag="${entry:0:1}"
        if [[ "$tag" == "S" || "$tag" =~ [a-z] ]]; then
            echo "Remote checkout uses skip-worktree/assume-unchanged index flags." >&2
            return 2
        fi
    done <<<"$listing"
    return 0
}
reject_untracked_source_files() {
    local listing
    if ! listing="$(git ls-files --others --exclude-per-directory=.gitignore)"; then
        echo "Cannot inspect remote untracked files safely." >&2
        return 2
    fi
    if [[ -n "$listing" ]]; then
        echo "Remote checkout contains untracked, non-ignored files; refusing deployment." >&2
        return 2
    fi
    # Intentionally ignored runtime configuration/data remains external to the
    # reviewed commit and is permitted only when the tracked .gitignore says so.
    return 0
}
reject_ignored_build_inputs() {
    local listing directory_listing artifact entry
    for artifact in backend/vedetta sensor/vedetta-sensor telemetry/telemetry; do
        if [[ ( -e "$artifact" || -L "$artifact" ) &&
              ( ! -f "$artifact" || -L "$artifact" ) ]]; then
            echo "Remote checkout contains an unsupported ignored build artifact." >&2
            return 2
        fi
    done
    if ! listing="$(git ls-files --others --ignored --exclude-per-directory=.gitignore -- \
        backend frontend collector telemetry sensor siem/migrations \
        ':(exclude)backend/vedetta' \
        ':(exclude)sensor/vedetta-sensor' \
        ':(exclude)telemetry/telemetry' \
        ':(exclude,glob)frontend/node_modules/**' \
        ':(exclude,glob)frontend/dist/**' \
        ':(exclude)frontend/.env' \
        ':(exclude,glob)frontend/.env.*')"; then
        echo "Cannot inspect remote ignored build inputs safely." >&2
        return 2
    fi
    # The excluded frontend paths are absent from its Docker context. Generated
    # binaries are regular-file-only; every other ignored entry in a Docker/Go
    # build root is an unreviewed input and is rejected.
    if [[ -n "$listing" ]]; then
        echo "Remote checkout contains an ignored build input; refusing deployment." >&2
        return 2
    fi
    if ! directory_listing="$(git ls-files --others --ignored --exclude-per-directory=.gitignore \
        --directory -- backend frontend collector telemetry sensor siem/migrations)"; then
        echo "Cannot inspect remote ignored build directories safely." >&2
        return 2
    fi
    while IFS= read -r entry; do
        case "$entry" in
            ""|backend/vedetta|sensor/vedetta-sensor|telemetry/telemetry|\
            frontend/node_modules|frontend/node_modules/|\
            frontend/dist|frontend/dist/|frontend/.env|frontend/.env.*)
                ;;
            *)
                echo "Remote checkout contains an ignored build directory; refusing deployment." >&2
                return 2
                ;;
        esac
    done <<<"$directory_listing"
    return 0
}
reject_hidden_index_flags
reject_untracked_source_files
reject_ignored_build_inputs
verify_tracked_tree "$(git rev-parse --verify HEAD^{commit})"
actual_branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
if [[ "$actual_branch" != "$expected_branch" ]]; then
    echo "Remote checkout is on '$actual_branch', expected '$expected_branch'." >&2
    exit 2
fi
# Local and deployment clones may use different names for the same upstream.
# Resolve the deployment checkout's own branch remote rather than coupling it
# to the local push-remote spelling.
remote_name="$(git config --get "branch.$expected_branch.remote" || true)"
if [[ -z "$remote_name" ]] && git remote get-url origin >/dev/null 2>&1; then
    remote_name="origin"
fi
if [[ -z "$remote_name" || "$remote_name" == "." ||
      ! "$remote_name" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] ||
   ! git remote get-url "$remote_name" >/dev/null 2>&1; then
    echo "Remote checkout has no supported upstream for '$expected_branch'." >&2
    exit 2
fi
remote_url="$(git remote get-url "$remote_name")"
if [[ -z "$remote_url" || "$remote_url" == -* || "$remote_url" == *$'\n'* ||
      "$remote_url" == ext::* ]]; then
    echo "Remote checkout has an unsupported upstream URL." >&2
    exit 2
fi
case "$remote_url" in
    /*|file:///*|http://?*|https://?*|ssh://?*)
        ;;
    *)
        # Unknown URI schemes and the transport::address syntax invoke a
        # git-remote-* helper. Only an ordinary scp-style host:path fallback is
        # supported here.
        if [[ "$remote_url" == *://* || "$remote_url" == *::* ||
              ! "$remote_url" =~ ^([A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+:.+ ]]; then
            echo "Remote checkout upstream must be an explicit supported URL or absolute path." >&2
            exit 2
        fi
        ;;
esac
if git remote get-url "$remote_url" >/dev/null 2>&1; then
    echo "Remote checkout upstream URL ambiguously names another configured remote." >&2
    exit 2
fi

git fetch --no-tags --no-recurse-submodules --no-auto-maintenance \
    --upload-pack=git-upload-pack "$remote_url" "refs/heads/$expected_branch"
fetched_head="$(git rev-parse --verify FETCH_HEAD^{commit})"
if [[ "$fetched_head" != "$expected_head" ]]; then
    echo "Published branch moved after review; refusing to deploy a different commit." >&2
    exit 2
fi
if ! git merge-base --is-ancestor HEAD "$expected_head"; then
    echo "Remote checkout cannot fast-forward to the reviewed commit." >&2
    exit 2
fi
git merge --ff-only --no-verify-signatures --no-gpg-sign --no-autostash \
    --no-edit --no-stat --no-verify "$expected_head"
if [[ "$(git rev-parse --verify HEAD^{commit})" != "$expected_head" ]]; then
    echo "Remote checkout did not reach the reviewed commit." >&2
    exit 2
fi
reject_hidden_index_flags
reject_untracked_source_files
reject_ignored_build_inputs
verify_tracked_tree "$expected_head"
REMOTE_SCRIPT

# The checkout verifier above is supplied on ssh's stdin. Run the updater in a
# second session so its fd 0 remains connected to the operator for an
# interactive sensor-service choice. Do not execute the mutable worktree path:
# a checkout that moves between sessions could replace update-all.sh before its
# in-script exact-HEAD check. This launcher is supplied by the reviewed local
# deploy.sh, independently checks HEAD, and sources both executable shell files
# from the reviewed commit's Git objects on dedicated file descriptors.
update_launcher=""
IFS= read -r -d '' update_launcher <<'REMOTE_LAUNCHER' || true
set -euo pipefail

remote_dir="$1"
expected_head="$2"
cd -- "$remote_dir"
remote_dir="$(pwd -P)"
git_dir="$remote_dir/.git"
if [[ ! -d "$git_dir" || -L "$git_dir" ]]; then
    echo "Remote deployment requires a canonical, non-linked .git directory." >&2
    exit 2
fi
git_bin="$(command -v git)"
git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_COMMON_DIR \
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
        "$git_bin" --no-replace-objects -C "$remote_dir" \
        --git-dir="$git_dir" --work-tree="$remote_dir" \
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
reject_unsafe_git_metadata() {
    local configured_keys key promisor_file
    if [[ ! -f "$git_dir/config" || -L "$git_dir/config" ||
          ! -f "$git_dir/HEAD" || -L "$git_dir/HEAD" ||
          ! -f "$git_dir/index" || -L "$git_dir/index" ||
          ! -d "$git_dir/objects" || -L "$git_dir/objects" ]]; then
        echo "Remote deployment requires regular, local Git control files." >&2
        return 2
    fi
    if [[ -e "$git_dir/commondir" || -L "$git_dir/commondir" ||
          -e "$git_dir/config.worktree" || -L "$git_dir/config.worktree" ||
          -e "$git_dir/objects/info/alternates" || -L "$git_dir/objects/info/alternates" ||
          -e "$git_dir/info/grafts" || -L "$git_dir/info/grafts" ]]; then
        echo "Remote Git metadata redirects the reviewed repository or object graph." >&2
        return 2
    fi
    if ! configured_keys="$(
        git config --local --includes --name-only --get-regexp '.*' |
            LC_ALL=C tr '[:upper:]' '[:lower:]'
    )"; then
        echo "Remote Git configuration cannot be inspected safely." >&2
        return 2
    fi
    while IFS= read -r key; do
        case "$key" in
            filter.*)
                echo "Remote Git metadata configures an unreviewed clean/smudge filter." >&2
                return 2
                ;;
            branch.*.mergeoptions|core.alternaterefscommand|core.askpass|\
            core.gitproxy|core.sshcommand|credential.helper|credential.*.helper|\
            extensions.partialclone|fetch.bundleuri|gc.recentobjectshook|\
            gpg.program|gpg.*.program|include.*|includeif.*|merge.*.driver|\
            merge.verifysignatures|protocol.allow|protocol.*.allow|\
            remote.*.partialclonefilter|remote.*.promisor|remote.*.uploadpack|\
            remote.*.vcs|submodule.*.update|\
            url.*.insteadof|url.*.pushinsteadof)
                echo "Remote Git metadata configures an unsupported external executor or object source." >&2
                return 2
                ;;
        esac
    done <<<"$configured_keys"
    for promisor_file in "$git_dir"/objects/pack/*.promisor; do
        if [[ -e "$promisor_file" || -L "$promisor_file" ]]; then
            echo "Remote deployment does not support a partial/promisor object store." >&2
            return 2
        fi
    done
    return 0
}
reject_unsafe_git_metadata

actual_head="$(git rev-parse --verify HEAD^{commit})"
if [[ "$actual_head" != "$expected_head" ]]; then
    echo "Remote checkout moved before reviewed updater launch: expected $expected_head, found $actual_head." >&2
    exit 2
fi

updater_entry="$(git ls-tree "$expected_head" -- scripts/update-all.sh)"
read -r updater_mode updater_type updater_blob updater_path <<<"$updater_entry"
if [[ "$updater_mode" != "100755" || "$updater_type" != "blob" ||
      "$updater_path" != "scripts/update-all.sh" ]]; then
    echo "Reviewed commit does not contain a regular executable updater." >&2
    exit 2
fi

port_config_entry="$(git ls-tree "$expected_head" -- scripts/lib/port-config.sh)"
read -r port_config_mode port_config_type port_config_blob port_config_path <<<"$port_config_entry"
if [[ "$port_config_mode" != "100644" || "$port_config_type" != "blob" ||
      "$port_config_path" != "scripts/lib/port-config.sh" ]]; then
    echo "Reviewed commit does not contain a regular port configuration helper." >&2
    exit 2
fi

git cat-file -e "$updater_blob^{blob}"
git cat-file -e "$port_config_blob^{blob}"
updater_size="$(git cat-file -s "$updater_blob")"
if [[ ! "$updater_size" =~ ^[0-9]+$ || "$updater_size" -gt 131072 ]]; then
    echo "Reviewed updater exceeds the safe immutable-launch size." >&2
    exit 2
fi
if ! reviewed_updater="$(git cat-file blob "$updater_blob")"; then
    echo "Reviewed updater could not be read from the expected commit." >&2
    exit 2
fi
export VEDETTA_EXPECTED_HEAD="$expected_head"
export VEDETTA_PINNED_PORT_CONFIG_FD=4

# Bash receives the reviewed updater program as its -c argument, so fd 0 stays
# connected to the operator. The inner shell uses the normal worktree path as
# $0 solely so SCRIPT_DIR resolves to the deployment repository; no bytes are
# read from that mutable updater path.
exec bash -c "$reviewed_updater" "$remote_dir/scripts/update-all.sh" \
    4< <(git cat-file blob "$port_config_blob")
REMOTE_LAUNCHER
update_command="bash -c $(quote_remote_arg "$update_launcher") -- $(quote_remote_arg "$REMOTE_DIR") $(quote_remote_arg "$scanned_head")"
echo "==> Building and restarting reviewed commit on $DEPLOY_HOST..."
"$ssh_bin" "$DEPLOY_HOST" "$update_command"

echo "==> Deploy complete at $scanned_head."
