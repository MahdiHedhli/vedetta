#!/usr/bin/env bash
# Inspect a pull request with the sanitation implementation from its trusted base.
#
# This script is designed for the base-owned pull_request_target workflow. It
# fetches candidate objects into a temporary Git repository, populates only an
# index, and never checks out or executes pull-request files.

set -euo pipefail
set +x
set +a
REPOSITORY_TOKEN="${VEDETTA_REPOSITORY_TOKEN:-}"
export -n REPOSITORY_TOKEN
unset VEDETTA_REPOSITORY_TOKEN VEDETTA_GIT_AUTH_HEADER
export GIT_NO_REPLACE_OBJECTS=1
unset GIT_CONFIG GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_TEMPLATE_DIR
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
TRUSTED_ROOT_INPUT="${VEDETTA_TRUSTED_ROOT:-$SCRIPT_DIR/..}"
TRUSTED_ROOT="$(CDPATH= cd -- "$TRUSTED_ROOT_INPUT" && pwd -P)" || {
    echo "Trusted PR sanitation failed: trusted root is unavailable" >&2
    exit 2
}
REPOSITORY_URL="${VEDETTA_REPOSITORY_URL:?Set VEDETTA_REPOSITORY_URL}"
PR_NUMBER="${VEDETTA_PR_NUMBER:?Set VEDETTA_PR_NUMBER}"
BASE_REF="${VEDETTA_BASE_REF:?Set VEDETTA_BASE_REF}"
BASE_SHA="${VEDETTA_BASE_SHA:?Set VEDETTA_BASE_SHA}"
HEAD_SHA="${VEDETTA_HEAD_SHA:?Set VEDETTA_HEAD_SHA}"
MERGE_SHA="${VEDETTA_MERGE_SHA:?Set VEDETTA_MERGE_SHA}"

die() {
    echo "Trusted PR sanitation failed: $*" >&2
    exit 2
}

valid_oid() {
    [[ "$1" =~ ^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$ ]]
}

[[ "$PR_NUMBER" =~ ^[1-9][0-9]*$ ]] || die "pull-request number is invalid"
valid_oid "$BASE_SHA" || die "base commit ID is invalid"
valid_oid "$HEAD_SHA" || die "head commit ID is invalid"
valid_oid "$MERGE_SHA" || die "merge commit ID is invalid"
git check-ref-format "refs/heads/$BASE_REF" >/dev/null 2>&1 || die "base branch name is invalid"
if [[ -z "$REPOSITORY_URL" || "$REPOSITORY_URL" == -* || "$REPOSITORY_URL" == *$'\n'* ]]; then
    die "repository URL is invalid"
fi
if [[ "$REPOSITORY_TOKEN" == *$'\n'* || "$REPOSITORY_TOKEN" == *$'\r'* ]]; then
    die "repository token is invalid"
fi
if [[ "${GITHUB_ACTIONS:-}" == true && -z "$REPOSITORY_TOKEN" ]]; then
    die "repository token is required in GitHub Actions"
fi

protected_policy_paths=(
    .github/workflows/trusted-repository-sanitation.yml
    scripts/run-trusted-pr-sanitation.sh
    scripts/check-repo-sanitization.sh
    scripts/check_repo_sanitization.py
    scripts/select-sanitation-range.sh
    scripts/tests/repo-sanitization-test.sh
    scripts/tests/trusted-pr-sanitation-test.sh
    threat-network/internal/corpus/canonical_test.go
    threat-network/internal/corpus/privacy_test.go
)
for trusted_file in "${protected_policy_paths[@]}"; do
    [[ -f "$TRUSTED_ROOT/$trusted_file" && ! -L "$TRUSTED_ROOT/$trusted_file" ]] ||
        die "trusted sanitation implementation is incomplete"
done

trusted_head="$(git -C "$TRUSTED_ROOT" rev-parse --verify HEAD^{commit})" ||
    die "trusted checkout has no commit"
[[ "$trusted_head" == "$BASE_SHA" ]] ||
    die "trusted checkout is not the pull-request base commit"
git -C "$TRUSTED_ROOT" diff --quiet -- || die "trusted checkout worktree is dirty"
git -C "$TRUSTED_ROOT" diff --cached --quiet -- || die "trusted checkout index is dirty"

temp_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
[[ -d "$temp_parent" ]] || die "temporary directory is unavailable"
INSPECTION_ROOT="$(mktemp -d "$temp_parent/vedetta-pr-sanitation.XXXXXX")"
cleanup() {
    rm -rf -- "$INSPECTION_ROOT"
}
trap cleanup EXIT HUP INT TERM

git init -q "$INSPECTION_ROOT"
git -C "$INSPECTION_ROOT" remote add origin "$REPOSITORY_URL"
fetch_refspecs=(
    "+refs/heads/$BASE_REF:refs/vedetta/base-branch"
    "+refs/pull/$PR_NUMBER/head:refs/vedetta/pr-head"
    "+refs/pull/$PR_NUMBER/merge:refs/vedetta/pr-merge"
)
fetch_status=0
if [[ -n "$REPOSITORY_TOKEN" ]]; then
    [[ "$REPOSITORY_URL" == https://* ]] ||
        die "authenticated repository URL must use HTTPS"
    if ! auth_payload="$(
        printf 'x-access-token:%s' "$REPOSITORY_TOKEN" | base64 | tr -d '\r\n'
    )" || [[ -z "$auth_payload" ]]; then
        die "repository authentication header could not be prepared"
    fi
    auth_header="AUTHORIZATION: basic $auth_payload"
    unset REPOSITORY_TOKEN
    if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
        printf '%b%s%b%s\n' '\072\072' add-mask '\072\072' "$auth_payload"
    fi

    # Keep the read-only workflow token out of the URL, repository config, and
    # argv. The URL-scoped header exists only for this fetch; tracing, prompts,
    # and configured credential helpers are disabled so it cannot be disclosed
    # or diverted through an auxiliary authentication program.
    (
        unset GIT_CONFIG GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_EXEC_PATH \
            GIT_SSL_NO_VERIFY GIT_TRACE GIT_TRACE_PACKET GIT_TRACE_CURL \
            GIT_TRACE_CURL_NO_DATA GIT_CURL_VERBOSE GIT_TRACE2 \
            GIT_TRACE2_EVENT GIT_TRACE2_PERF
        export VEDETTA_GIT_AUTH_HEADER="$auth_header"
        export GIT_ALLOW_PROTOCOL=https GIT_PROTOCOL_FROM_USER=0
        export GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false
        export SSH_ASKPASS_REQUIRE=never GIT_TERMINAL_PROMPT=0
        git -c http.extraHeader= -c "http.${REPOSITORY_URL}.extraHeader=" \
            --config-env="http.${REPOSITORY_URL}.extraHeader=VEDETTA_GIT_AUTH_HEADER" \
            -c credential.helper= -c credential.interactive=false \
            -c core.askPass=/bin/false -c core.hooksPath=/dev/null \
            -c maintenance.auto=false -c gc.auto=0 \
            -c http.sslVerify=true -c http.followRedirects=false \
            -C "$INSPECTION_ROOT" fetch --quiet --no-tags \
            --no-recurse-submodules --no-auto-maintenance \
            origin "${fetch_refspecs[@]}"
    ) || fetch_status=$?
    unset auth_header auth_payload
else
    unset REPOSITORY_TOKEN
    git -C "$INSPECTION_ROOT" fetch --quiet --no-tags --no-recurse-submodules \
        origin "${fetch_refspecs[@]}" || fetch_status=$?
fi
[[ "$fetch_status" -eq 0 ]] || die "required base or pull-request refs could not be fetched"

fetched_head="$(git -C "$INSPECTION_ROOT" rev-parse --verify refs/vedetta/pr-head^{commit})" ||
    die "pull-request head is not a commit"
fetched_merge="$(git -C "$INSPECTION_ROOT" rev-parse --verify refs/vedetta/pr-merge^{commit})" ||
    die "pull-request merge ref is not a commit"
fetched_base="$(git -C "$INSPECTION_ROOT" rev-parse --verify refs/vedetta/base-branch^{commit})" ||
    die "base branch is not a commit"
git -C "$INSPECTION_ROOT" cat-file -e "$BASE_SHA^{commit}" 2>/dev/null ||
    die "event base commit is unavailable"
[[ "$fetched_base" == "$BASE_SHA" ]] || die "base branch moved after the pull-request event"
[[ "$fetched_head" == "$HEAD_SHA" ]] || die "pull-request head moved during inspection"
[[ "$fetched_merge" == "$MERGE_SHA" ]] || die "pull-request merge ref moved during inspection"

parent_line="$(git -C "$INSPECTION_ROOT" rev-list --parents -n 1 "$MERGE_SHA")"
read -r merge_commit merge_base_parent merge_head_parent merge_extra <<<"$parent_line"
if [[ "$merge_commit" != "$MERGE_SHA" || "$merge_base_parent" != "$BASE_SHA" ||
      "$merge_head_parent" != "$HEAD_SHA" || -n "${merge_extra:-}" ]]; then
    die "pull-request merge commit does not have the exact event base and head parents"
fi
printf 'Trusted PR objects: PR %s base=%s head=%s merge=%s\n' \
    "$PR_NUMBER" "$BASE_SHA" "$HEAD_SHA" "$MERGE_SHA"

# Policy code is immutable through an ordinary PR so a clean candidate cannot
# disable the gate for the next PR. The three whole-file checker exemptions in
# this list receive the same protection. Inspect every introduced commit, not
# just the final tree: an unsafe exempt blob must not be committed briefly and
# restored before merge.
protected_commits=("$MERGE_SHA")
while IFS= read -r candidate_commit; do
    [[ -n "$candidate_commit" ]] && protected_commits+=("$candidate_commit")
done < <(git -C "$INSPECTION_ROOT" rev-list "$BASE_SHA..$HEAD_SHA")

for protected_path in "${protected_policy_paths[@]}"; do
    base_entry="$(git -C "$INSPECTION_ROOT" ls-tree "$BASE_SHA" -- "$protected_path")"
    [[ -n "$base_entry" ]] || die "trusted policy path is absent from the base commit: $protected_path"
    for candidate_commit in "${protected_commits[@]}"; do
        candidate_entry="$(git -C "$INSPECTION_ROOT" ls-tree "$candidate_commit" -- "$protected_path")"
        [[ "$candidate_entry" == "$base_entry" ]] ||
            die "pull request changes a protected sanitation policy path: $protected_path in $candidate_commit"
    done
done

# Populate the index from the proposed merge tree. No candidate worktree is
# materialized, so executable bits, hooks, dependencies, and workflow files are
# inspected only as Git metadata and blobs.
git -C "$INSPECTION_ROOT" read-tree "$MERGE_SHA"

range_output="$({
    cd "$INSPECTION_ROOT"
    env -u GITHUB_OUTPUT \
        SANITATION_EVENT_NAME=pull_request \
        SANITATION_REF_TYPE=branch \
        SANITATION_REF_NAME="$BASE_REF" \
        SANITATION_BASE_SHA="$BASE_SHA" \
        SANITATION_HEAD_SHA="$HEAD_SHA" \
        SANITATION_DEFAULT_BRANCH="$BASE_REF" \
        bash "$TRUSTED_ROOT/scripts/select-sanitation-range.sh"
})"
expected_range="true"$'\t'"$BASE_SHA..$HEAD_SHA"
[[ "$range_output" == "$expected_range" ]] || die "trusted range selector returned an unexpected range"

bash "$TRUSTED_ROOT/scripts/check-repo-sanitization.sh" \
    "$INSPECTION_ROOT" --history-range "$BASE_SHA..$HEAD_SHA"
printf 'Trusted PR sanitation passed for head %s and merge %s.\n' "$HEAD_SHA" "$MERGE_SHA"
