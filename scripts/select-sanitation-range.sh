#!/usr/bin/env bash
# Select the committed trees that a GitHub PR/push is introducing.
#
# This helper is intentionally shared by the required main/PR CI gate and the
# lightweight all-ref push detector. GitHub push workflows are post-receive:
# they detect a bad unprotected branch/tag after publication; only protected
# PR/required-check rules can prevent publication to main.

set -euo pipefail

event_name="${SANITATION_EVENT_NAME:?Set SANITATION_EVENT_NAME}"
ref_type="${SANITATION_REF_TYPE:-}"
ref_name="${SANITATION_REF_NAME:-}"
before_sha="${SANITATION_BEFORE_SHA:-}"
head_sha="${SANITATION_HEAD_SHA:-}"
base_sha="${SANITATION_BASE_SHA:-}"
default_branch="${SANITATION_DEFAULT_BRANCH:-main}"

is_absent_or_zero_sha() {
    [[ -z "$1" || "$1" =~ ^0+$ ]]
}

is_full_zero_sha() {
    [[ "$1" =~ ^(0{40}|0{64})$ ]]
}

commit_oid() {
    git rev-parse --verify "$1^{commit}" 2>/dev/null
}

emit() {
    local should_scan="$1"
    local range="${2:-}"
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        printf 'should_scan=%s\nrange=%s\n' "$should_scan" "$range" >>"$GITHUB_OUTPUT"
    else
        printf '%s\t%s\n' "$should_scan" "$range"
    fi
}

if [[ "$event_name" == "pull_request" ]]; then
    base_commit="$(commit_oid "$base_sha")" || {
        echo "Cannot resolve pull-request base commit" >&2
        exit 2
    }
    head_commit="$(commit_oid "$head_sha")" || {
        echo "Cannot resolve pull-request head commit" >&2
        exit 2
    }
    emit true "$base_commit..$head_commit"
    exit 0
fi

if [[ "$event_name" != "push" ]]; then
    echo "Unsupported sanitation event: $event_name" >&2
    exit 2
fi

if [[ "$ref_type" != "branch" && "$ref_type" != "tag" ]]; then
    echo "Push sanitation requires ref type 'branch' or 'tag'" >&2
    exit 2
fi
if [[ -z "$ref_name" ]]; then
    echo "Push sanitation requires a nonempty ref name" >&2
    exit 2
fi
ref_namespace="heads"
[[ "$ref_type" == "tag" ]] && ref_namespace="tags"
if ! git check-ref-format "refs/$ref_namespace/$ref_name" >/dev/null 2>&1; then
    echo "Pushed ref name is not a safe Git ref" >&2
    exit 2
fi
if [[ -z "$head_sha" ]]; then
    echo "Push sanitation requires github.event.after" >&2
    exit 2
fi

# A ref deletion publishes no new tree. github.event.after, unlike github.sha,
# is reliably all-zero for both branch and tag deletion events.
if is_full_zero_sha "$head_sha"; then
    emit false ""
    exit 0
fi

head_commit="$(commit_oid "$head_sha")" || {
    echo "Cannot resolve pushed commit" >&2
    exit 2
}

# Normal updates and force-pushes use the exact before..after set. If the old
# object is unavailable after a force-push, fall through to a conservative
# default-branch anchor.
if ! is_absent_or_zero_sha "$before_sha"; then
    if before_commit="$(commit_oid "$before_sha")"; then
        emit true "$before_commit..$head_commit"
        exit 0
    fi
fi

if ! git check-ref-format "refs/heads/$default_branch" >/dev/null 2>&1; then
    echo "Repository default branch is not a safe Git ref" >&2
    exit 2
fi
default_ref="refs/remotes/origin/$default_branch"
default_commit="$(commit_oid "$default_ref" 2>/dev/null || true)"

# Recreating the default branch has no trustworthy predecessor, so inspect its
# complete reachable history. New unrelated refs receive the same treatment.
if [[ "$ref_type" == "branch" && "$ref_name" == "$default_branch" ]]; then
    emit true "$head_commit"
    exit 0
fi

merge_base=""
if [[ -n "$default_commit" ]]; then
    merge_base="$(git merge-base "$head_commit" "$default_commit" 2>/dev/null || true)"
fi
if [[ -z "$merge_base" ]]; then
    emit true "$head_commit"
elif [[ "$merge_base" == "$head_commit" ]]; then
    # A new branch/tag at an already-published default-branch commit introduces
    # no history. Scan the exact target tree without rescanning all ancestors.
    emit true "$head_commit^!"
else
    emit true "$merge_base..$head_commit"
fi
