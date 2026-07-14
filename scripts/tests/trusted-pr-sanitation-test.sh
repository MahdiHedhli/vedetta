#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
RUNNER="$ROOT/scripts/run-trusted-pr-sanitation.sh"
WORKFLOW="$ROOT/.github/workflows/trusted-repository-sanitation.yml"
REAL_GIT="$(command -v git)"
REAL_DIRNAME="$(command -v dirname)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

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

workflow_has_no_writable_permissions() {
    ! sed -E 's/[[:space:]]+#.*$//' "$1" |
        tr -d "\"'" |
        grep -Eiq '(^|[[:space:]{,])permissions:[[:space:]]*write-all([[:space:]},#]|$)|(^|[[:space:]{,])[A-Za-z0-9_-]+:[[:space:]]*write([[:space:]},#]|$)'
}

file_sha256() {
    python3 - "$1" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

git_identity() {
    git -C "$1" config user.name "Vedetta trusted sanitation test"
    git -C "$1" config user.email "trusted-sanitation@vedetta.example"
}

UNSAFE_VALUE="$(printf '%d.%d.%d.%d' 192 168 77 9)"
BARE="$TMP/repository.git"
TRUSTED="$TMP/trusted"
RUNNER_TEMP="$TMP/runner-temp"
SHADOW_MARKER="$TMP/python-shadow-ran"
OUTER_GITHUB_OUTPUT="$TMP/outer-github-output"
AUTH_BIN="$TMP/auth-bin"
AUTH_LOG="$TMP/auth-fetch.log"
PRE_FETCH_CHILD_LOG="$TMP/pre-fetch-child.log"
HOSTILE_GLOBAL_CONFIG="$TMP/hostile-global.gitconfig"
HOSTILE_SYSTEM_CONFIG="$TMP/hostile-system.gitconfig"
HOSTILE_TEMPLATE="$TMP/hostile-template"
mkdir -p "$RUNNER_TEMP"
mkdir -p "$AUTH_BIN"
mkdir -p "$HOSTILE_TEMPLATE"

git config --file "$HOSTILE_GLOBAL_CONFIG" init.templateDir "$HOSTILE_TEMPLATE"
git config --file "$HOSTILE_GLOBAL_CONFIG" \
    "url.file://$TMP/global-diversion/.insteadOf" 'https://ghe.example/'
git config --file "$HOSTILE_SYSTEM_CONFIG" \
    "url.file://$TMP/system-diversion/.insteadOf" 'https://ghe.example/'
git config --file "$HOSTILE_TEMPLATE/config" \
    "url.file://$TMP/template-diversion/.insteadOf" 'https://ghe.example/'

printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "token=%s\\nrepository_token=%s\\nheader=%s\\n" "${VEDETTA_REPOSITORY_TOKEN-}" "${REPOSITORY_TOKEN-}" "${VEDETTA_GIT_AUTH_HEADER-}" >>"${VEDETTA_TEST_PRE_FETCH_CHILD_LOG:?}"' \
    'exec "${VEDETTA_TEST_REAL_DIRNAME:?}" "$@"' >"$AUTH_BIN/dirname"
chmod +x "$AUTH_BIN/dirname"

printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'args=("$@")' \
    'repo=' \
    'for ((i = 0; i < ${#args[@]}; i++)); do' \
    '  if [[ "${args[$i]}" == -C && $((i + 1)) -lt ${#args[@]} ]]; then repo="${args[$((i + 1))]}"; fi' \
    'done' \
    'case " $* " in' \
    '  *" fetch "*)' \
    '    printf "%s\n" \' \
    '      "argv=$*" \' \
    '      "token=${VEDETTA_REPOSITORY_TOKEN-}" \' \
    '      "repository_token=${REPOSITORY_TOKEN-}" \' \
    '      "header=${VEDETTA_GIT_AUTH_HEADER-}" \' \
    '      "allow=${GIT_ALLOW_PROTOCOL-}" \' \
    '      "git_askpass=${GIT_ASKPASS-}" \' \
    '      "ssh_askpass=${SSH_ASKPASS-}" \' \
    '      "terminal_prompt=${GIT_TERMINAL_PROMPT-}" \' \
    '      "trace=${GIT_TRACE-}${GIT_TRACE_CURL-}${GIT_CURL_VERBOSE-}${GIT_TRACE2-}" \' \
    '      "config_nosystem=${GIT_CONFIG_NOSYSTEM-}" \' \
    '      "config_global=${GIT_CONFIG_GLOBAL-}" \' \
    '      "config_system=${GIT_CONFIG_SYSTEM-}" \' \
    '      "origin=$("${VEDETTA_TEST_REAL_GIT:?}" -C "$repo" remote get-url origin)" \' \
    '      "local_rewrites=$("${VEDETTA_TEST_REAL_GIT:?}" -C "$repo" config --local --get-regexp "^url\\..*\\.(insteadof|pushinsteadof)$" || true)" \' \
    '      "persisted_header=$("${VEDETTA_TEST_REAL_GIT:?}" -C "$repo" config --local --get-regexp "^http\\..*\\.extraheader$" || true)" \' \
    '      >"${VEDETTA_TEST_AUTH_LOG:?}"' \
    '    "${VEDETTA_TEST_REAL_GIT:?}" -C "$repo" remote set-url origin "${VEDETTA_TEST_AUTH_BARE:?}"' \
    '    export GIT_ALLOW_PROTOCOL=https:file' \
    '    ;;' \
    'esac' \
    'exec "${VEDETTA_TEST_REAL_GIT:?}" "$@"' >"$AUTH_BIN/git"
chmod +x "$AUTH_BIN/git"

git init -q --bare --initial-branch=main "$BARE"
git init -q -b main "$TRUSTED"
git_identity "$TRUSTED"
mkdir -p \
    "$TRUSTED/.github/workflows" \
    "$TRUSTED/scripts/tests" \
    "$TRUSTED/threat-network/internal/corpus" \
    "$TRUSTED/corpus"
cp "$ROOT/scripts/check-repo-sanitization.sh" "$TRUSTED/scripts/check-repo-sanitization.sh"
cp "$ROOT/scripts/check_repo_sanitization.py" "$TRUSTED/scripts/check_repo_sanitization.py"
cp "$ROOT/scripts/select-sanitation-range.sh" "$TRUSTED/scripts/select-sanitation-range.sh"
cp "$ROOT/scripts/run-trusted-pr-sanitation.sh" "$TRUSTED/scripts/run-trusted-pr-sanitation.sh"
cp "$ROOT/scripts/tests/trusted-pr-sanitation-test.sh" "$TRUSTED/scripts/tests/trusted-pr-sanitation-test.sh"
cp "$ROOT/.github/workflows/trusted-repository-sanitation.yml" "$TRUSTED/.github/workflows/trusted-repository-sanitation.yml"
printf '%s\n' \
    'import os' \
    'with open(os.environ["VEDETTA_TEST_SHADOW_MARKER"], "w", encoding="utf-8") as marker:' \
    '    marker.write("untrusted sibling imported")' \
    'raise SystemExit(0)' >"$TRUSTED/scripts/subprocess.py"
printf '%s\n' '# trusted regression placeholder' >"$TRUSTED/scripts/tests/repo-sanitization-test.sh"
printf '%s\n' 'package corpus' >"$TRUSTED/threat-network/internal/corpus/canonical_test.go"
printf '%s\n' 'package corpus' >"$TRUSTED/threat-network/internal/corpus/privacy_test.go"
printf '%s\n' '{"ip":"192.0.2.8","host":"router.example"}' >"$TRUSTED/corpus/base.json"
git -C "$TRUSTED" add .
git -C "$TRUSTED" commit -qm base
BASE_SHA="$(git -C "$TRUSTED" rev-parse HEAD)"
git -C "$TRUSTED" remote add origin "$BARE"
git -C "$TRUSTED" push -qu -u origin main

PR_NUMBER=0
new_candidate() {
    local name="$1"
    PR_NUMBER=$((PR_NUMBER + 1))
    CANDIDATE="$TMP/candidate-$name"
    git clone -q "$BARE" "$CANDIDATE"
    git_identity "$CANDIDATE"
    git -C "$CANDIDATE" switch -qc "$name"
}

commit_candidate() {
    local message="$1"
    git -C "$CANDIDATE" add -A
    git -C "$CANDIDATE" commit -qm "$message"
}

publish_pr() {
    local merge_tree="${1:-}"
    HEAD_SHA="$(git -C "$CANDIDATE" rev-parse HEAD)"
    [[ -n "$merge_tree" ]] || merge_tree="$(git -C "$CANDIDATE" rev-parse HEAD^{tree})"
    MERGE_SHA="$(printf '%s\n' merge | git -C "$CANDIDATE" commit-tree "$merge_tree" -p "$BASE_SHA" -p "$HEAD_SHA")"
    git -C "$CANDIDATE" push -q --force origin \
        "$HEAD_SHA:refs/pull/$PR_NUMBER/head" \
        "$MERGE_SHA:refs/pull/$PR_NUMBER/merge"
}

run_scan() {
    local expected_head="${1:-$HEAD_SHA}" expected_merge="${2:-$MERGE_SHA}"
    OUTPUT="$TMP/scan-$PR_NUMBER.out"
    : >"$OUTER_GITHUB_OUTPUT"
    set +e
    RUNNER_TEMP="$RUNNER_TEMP" \
    GITHUB_OUTPUT="$OUTER_GITHUB_OUTPUT" \
    VEDETTA_TRUSTED_ROOT="$TRUSTED" \
    VEDETTA_REPOSITORY_URL="${VEDETTA_TEST_REPOSITORY_URL:-$BARE}" \
    VEDETTA_REPOSITORY_TOKEN="${VEDETTA_TEST_REPOSITORY_TOKEN:-}" \
    REPOSITORY_TOKEN="${VEDETTA_TEST_AMBIENT_REPOSITORY_TOKEN:-}" \
    GITHUB_ACTIONS="${VEDETTA_TEST_GITHUB_ACTIONS:-false}" \
    VEDETTA_PR_NUMBER="$PR_NUMBER" \
    VEDETTA_BASE_REF=main \
    VEDETTA_BASE_SHA="$BASE_SHA" \
    VEDETTA_HEAD_SHA="$expected_head" \
    VEDETTA_MERGE_SHA="$expected_merge" \
    VEDETTA_TEST_SHADOW_MARKER="$SHADOW_MARKER" \
    VEDETTA_TEST_REAL_GIT="$REAL_GIT" \
    VEDETTA_TEST_REAL_DIRNAME="$REAL_DIRNAME" \
    VEDETTA_TEST_AUTH_LOG="$AUTH_LOG" \
    VEDETTA_TEST_PRE_FETCH_CHILD_LOG="$PRE_FETCH_CHILD_LOG" \
    VEDETTA_TEST_AUTH_BARE="$BARE" \
        bash -a "$RUNNER" >"$OUTPUT" 2>&1
    SCAN_RC=$?
    set -e
}

new_candidate clean
printf '%s\n' '{"ip":"198.51.100.8","host":"candidate.example"}' >"$CANDIDATE/corpus/candidate.json"
commit_candidate clean
publish_pr
ORIGINAL_PATH="$PATH"
PATH="$AUTH_BIN:$PATH"
VEDETTA_TEST_REPOSITORY_URL='https://ghe.example/owner/repository.git'
VEDETTA_TEST_REPOSITORY_TOKEN='synthetic-read-token'
VEDETTA_TEST_AMBIENT_REPOSITORY_TOKEN='ambient-repository-token'
GIT_CONFIG_GLOBAL="$HOSTILE_GLOBAL_CONFIG" \
GIT_CONFIG_SYSTEM="$HOSTILE_SYSTEM_CONFIG" \
    run_scan
PATH="$ORIGINAL_PATH"
unset VEDETTA_TEST_REPOSITORY_URL VEDETTA_TEST_REPOSITORY_TOKEN \
    VEDETTA_TEST_AMBIENT_REPOSITORY_TOKEN
if [[ "$SCAN_RC" -ne 0 ]]; then
    printf 'trusted authenticated fixture failed:\n%s\n' "$(cat "$OUTPUT")" >&2
fi
is "$SCAN_RC" "0" "clean pull-request objects pass the trusted base policy"
ok test ! -e "$SHADOW_MARKER" "trusted checker isolates standard-library imports from repository siblings"
ok test ! -s "$OUTER_GITHUB_OUTPUT" "trusted selector cannot inherit the workflow step output channel"
ok grep -Fq "Trusted PR objects: PR $PR_NUMBER base=$BASE_SHA head=$HEAD_SHA merge=$MERGE_SHA" "$OUTPUT" "trusted log identifies the exact inspected objects"
ok grep -Fq "Trusted PR sanitation passed for head $HEAD_SHA and merge $MERGE_SHA" "$OUTPUT" "trusted log records exact-object success"
ok test -s "$PRE_FETCH_CHILD_LOG" "authenticated fixture observes a pre-fetch child process"
ok bash -c '! grep -Fq -- "$1" "$2" && ! grep -Fq -- "$3" "$2"' _ \
    synthetic-read-token "$PRE_FETCH_CHILD_LOG" 'AUTHORIZATION:' \
    "pre-fetch child processes inherit neither the raw token nor authorization header"
ok grep -Fxq 'repository_token=' "$PRE_FETCH_CHILD_LOG" "saved token is de-exported before pre-fetch child processes"
ok grep -Fq -- '--config-env=http.https://ghe.example/owner/repository.git.extraHeader=VEDETTA_GIT_AUTH_HEADER' "$AUTH_LOG" "trusted fetch scopes its ephemeral header to the exact repository URL"
ok grep -Fq 'header=AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46c3ludGhldGljLXJlYWQtdG9rZW4=' "$AUTH_LOG" "trusted fetch receives the encoded read token through the config environment"
ok grep -Fxq 'token=' "$AUTH_LOG" "raw workflow token is removed before Git starts"
ok grep -Fxq 'repository_token=' "$AUTH_LOG" "saved raw token is absent from the Git environment"
ok grep -Fxq 'allow=https' "$AUTH_LOG" "authenticated fetch permits only HTTPS transport"
ok grep -Fxq 'git_askpass=/bin/false' "$AUTH_LOG" "authenticated fetch disables Git askpass"
ok grep -Fxq 'ssh_askpass=/bin/false' "$AUTH_LOG" "authenticated fetch disables SSH askpass"
ok grep -Fxq 'terminal_prompt=0' "$AUTH_LOG" "authenticated fetch disables terminal credential prompts"
ok grep -Fxq 'trace=' "$AUTH_LOG" "authenticated fetch clears Git tracing controls"
ok grep -Fxq 'config_nosystem=1' "$AUTH_LOG" "authenticated fetch suppresses system Git configuration"
ok grep -Fxq 'config_global=/dev/null' "$AUTH_LOG" "authenticated fetch suppresses global Git configuration"
ok grep -Fxq 'config_system=/dev/null' "$AUTH_LOG" "authenticated fetch pins the system config path to an empty file"
ok grep -Fxq 'origin=https://ghe.example/owner/repository.git' "$AUTH_LOG" "workflow token is absent from the configured repository URL"
ok grep -Fxq 'local_rewrites=' "$AUTH_LOG" "ambient init templates cannot persist URL rewrites in the inspection repository"
ok grep -Fxq 'persisted_header=' "$AUTH_LOG" "authenticated fetch persists no HTTP authorization header"
ok grep -Fq -- '-c credential.helper=' "$AUTH_LOG" "authenticated fetch disables configured credential helpers"
ok grep -Fq -- '-c http.sslVerify=true' "$AUTH_LOG" "authenticated fetch enforces TLS certificate verification"
ok grep -Fq -- '-c http.followRedirects=false' "$AUTH_LOG" "authenticated fetch cannot redirect its scoped authorization header"
ok grep -Fq -- '--no-auto-maintenance' "$AUTH_LOG" "authenticated fetch disables automatic maintenance"
ok bash -c '! grep -Fq -- "$1" "$2" && ! grep -Fq -- "$1" "$3"' _ \
    synthetic-read-token "$AUTH_LOG" "$OUTPUT" "raw workflow token is absent from Git argv and runner output"
AUTH_ARGV="$(sed -n 's/^argv=//p' "$AUTH_LOG")"
ok bash -c '[[ "$2" != *"$1"* ]] && ! grep -Fq -- "$1" "$3"' _ \
    eC1hY2Nlc3MtdG9rZW46c3ludGhldGljLXJlYWQtdG9rZW4= \
    "$AUTH_ARGV" "$OUTPUT" "encoded workflow token is absent from Git argv and runner output"

VEDETTA_TEST_GITHUB_ACTIONS=true
run_scan
unset VEDETTA_TEST_GITHUB_ACTIONS
ok test "$SCAN_RC" -ne 0 "GitHub Actions mode fails closed without its repository token"
ok grep -Fq 'repository token is required in GitHub Actions' "$OUTPUT" "missing Actions token has an explicit diagnostic"

VEDETTA_TEST_REPOSITORY_TOKEN='synthetic-read-token'
run_scan
unset VEDETTA_TEST_REPOSITORY_TOKEN
ok test "$SCAN_RC" -ne 0 "authenticated fetch refuses a non-HTTPS repository URL"
ok grep -Fq 'authenticated repository URL must use HTTPS' "$OUTPUT" "non-HTTPS authentication failure is explicit"
ok bash -c '! grep -Fq -- "$1" "$2"' _ synthetic-read-token "$OUTPUT" "authentication failure does not print the raw token"

new_candidate candidate-noops
MARKER="$TMP/candidate-code-ran"
printf '%s\n' "$UNSAFE_VALUE" >"$CANDIDATE/corpus/leak.txt"
printf '%s\n' '#!/usr/bin/env bash' "touch '$MARKER'" 'exit 0' >"$CANDIDATE/scripts/check-repo-sanitization.sh"
printf '%s\n' '#!/usr/bin/env python3' "open('$MARKER','w').close()" >"$CANDIDATE/scripts/check_repo_sanitization.py"
printf '%s\n' '#!/usr/bin/env bash' "touch '$MARKER'" 'printf "false\\t\\n"' >"$CANDIDATE/scripts/select-sanitation-range.sh"
printf '%s\n' '#!/usr/bin/env bash' "touch '$MARKER'" 'exit 0' >"$CANDIDATE/scripts/run-trusted-pr-sanitation.sh"
mkdir -p "$CANDIDATE/.github/workflows"
printf '%s\n' 'name: disabled' 'on: workflow_dispatch' >"$CANDIDATE/.github/workflows/trusted-repository-sanitation.yml"
commit_candidate malicious-candidate-gate
publish_pr
run_scan
ok test "$SCAN_RC" -ne 0 "candidate gate no-ops cannot hide a final-tree identifier"
ok test ! -e "$MARKER" "candidate checker, selector, and workflow code are never executed"

new_candidate policy-noops
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$CANDIDATE/scripts/check-repo-sanitization.sh"
printf '%s\n' '#!/usr/bin/env python3' 'raise SystemExit(0)' >"$CANDIDATE/scripts/check_repo_sanitization.py"
printf '%s\n' '#!/usr/bin/env bash' 'printf "false\\t\\n"' >"$CANDIDATE/scripts/select-sanitation-range.sh"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$CANDIDATE/scripts/run-trusted-pr-sanitation.sh"
printf '%s\n' 'name: disabled' 'on: workflow_dispatch' >"$CANDIDATE/.github/workflows/trusted-repository-sanitation.yml"
commit_candidate disable-future-policy
publish_pr
run_scan
ok test "$SCAN_RC" -ne 0 "clean candidate cannot disable the sanitation trust root for later pull requests"
ok grep -Fq 'protected sanitation policy path' "$OUTPUT" "trust-root mutation failure is explicit"

new_candidate add-delete-history
printf '%s\n' "$UNSAFE_VALUE" >"$CANDIDATE/corpus/transient.txt"
commit_candidate add-leak
git -C "$CANDIDATE" rm -q corpus/transient.txt
commit_candidate delete-leak
publish_pr
run_scan
ok test "$SCAN_RC" -ne 0 "trusted base range catches add-then-delete history"

new_candidate protected-exemption
printf '%s\n' 'package corpus' "const observed = \"$UNSAFE_VALUE\"" \
    >"$CANDIDATE/threat-network/internal/corpus/privacy_test.go"
commit_candidate alter-whole-file-exemption
publish_pr
run_scan
ok test "$SCAN_RC" -ne 0 "candidate changes to a whole-file sanitation exemption fail closed"
ok grep -Fq 'protected sanitation policy path' "$OUTPUT" "protected-exemption failure is explicit"

new_candidate protected-exemption-history
printf '%s\n' 'package corpus' "const observed = \"$UNSAFE_VALUE\"" \
    >"$CANDIDATE/threat-network/internal/corpus/privacy_test.go"
commit_candidate transient-exemption-leak
git -C "$CANDIDATE" checkout -q "$BASE_SHA" -- threat-network/internal/corpus/privacy_test.go
commit_candidate restore-exemption
publish_pr
run_scan
ok test "$SCAN_RC" -ne 0 "restoring an exempt blob cannot erase unsafe intermediate history"
ok grep -Fq 'protected sanitation policy path' "$OUTPUT" "exempt-history failure is explicit"

new_candidate merge-tree-only
printf '%s\n' '{"ip":"198.51.100.9"}' >"$CANDIDATE/corpus/head.json"
commit_candidate safe-head
HEAD_SHA="$(git -C "$CANDIDATE" rev-parse HEAD)"
printf '%s\n' "$UNSAFE_VALUE" >"$CANDIDATE/corpus/merge-only-leak.txt"
git -C "$CANDIDATE" add corpus/merge-only-leak.txt
UNSAFE_MERGE_TREE="$(git -C "$CANDIDATE" write-tree)"
git -C "$CANDIDATE" reset -q --hard "$HEAD_SHA"
publish_pr "$UNSAFE_MERGE_TREE"
run_scan
ok test "$SCAN_RC" -ne 0 "unsafe content present only in the proposed merge tree is inspected"

new_candidate wrong-event-head
printf '%s\n' '{"ip":"198.51.100.10"}' >"$CANDIDATE/corpus/head.json"
commit_candidate safe-head
publish_pr
run_scan "$BASE_SHA" "$MERGE_SHA"
ok test "$SCAN_RC" -ne 0 "event and fetched head mismatch fails closed"
ok grep -Fq 'head moved during inspection' "$OUTPUT" "head mismatch is explicit"

new_candidate wrong-merge-parents
printf '%s\n' '{"ip":"198.51.100.11"}' >"$CANDIDATE/corpus/head.json"
commit_candidate safe-head
HEAD_SHA="$(git -C "$CANDIDATE" rev-parse HEAD)"
TREE="$(git -C "$CANDIDATE" rev-parse HEAD^{tree})"
MERGE_SHA="$(printf '%s\n' merge | git -C "$CANDIDATE" commit-tree "$TREE" -p "$HEAD_SHA" -p "$BASE_SHA")"
git -C "$CANDIDATE" push -q --force origin \
    "$HEAD_SHA:refs/pull/$PR_NUMBER/head" \
    "$MERGE_SHA:refs/pull/$PR_NUMBER/merge"
run_scan
ok test "$SCAN_RC" -ne 0 "merge commit with reversed or unexpected parents fails closed"
ok grep -Fq 'exact event base and head parents' "$OUTPUT" "merge-parent mismatch is explicit"

new_candidate missing-merge-ref
printf '%s\n' '{"ip":"198.51.100.12"}' >"$CANDIDATE/corpus/head.json"
commit_candidate safe-head
HEAD_SHA="$(git -C "$CANDIDATE" rev-parse HEAD)"
MERGE_SHA="$(printf 'f%.0s' {1..40})"
git -C "$CANDIDATE" push -q --force origin "$HEAD_SHA:refs/pull/$PR_NUMBER/head"
run_scan
ok test "$SCAN_RC" -ne 0 "missing pull-request merge ref fails closed"

new_candidate moved-base
printf '%s\n' '{"ip":"198.51.100.13"}' >"$CANDIDATE/corpus/head.json"
commit_candidate safe-head
publish_pr
BASE_TREE="$(git -C "$CANDIDATE" rev-parse "$BASE_SHA^{tree}")"
ADVANCED_BASE="$(printf '%s\n' advanced-base | git -C "$CANDIDATE" commit-tree "$BASE_TREE" -p "$BASE_SHA")"
git -C "$CANDIDATE" push -q origin "$ADVANCED_BASE:refs/heads/main"
run_scan
ok test "$SCAN_RC" -ne 0 "base movement after the event fails closed instead of using stale policy"
ok grep -Fq 'base branch moved after the pull-request event' "$OUTPUT" "base-movement failure is explicit"
git --git-dir="$BARE" update-ref refs/heads/main "$BASE_SHA" "$ADVANCED_BASE"

ok grep -Fq 'pull_request_target:' "$WORKFLOW" "trusted workflow is base-context pull_request_target"
ok grep -Fq 'types: [opened, synchronize, reopened, ready_for_review, edited]' "$WORKFLOW" "base retargeting triggers a fresh trusted inspection"
ok grep -Fq 'contents: read' "$WORKFLOW" "trusted workflow grants read-only repository permission"
ok grep -Fq 'VEDETTA_REPOSITORY_TOKEN: ${{ github.token }}' "$WORKFLOW" "trusted workflow passes its job token only to the base-owned runner"
ok grep -Fq 'ref: ${{ github.event.pull_request.base.sha }}' "$WORKFLOW" "trusted workflow checks out the exact base policy"
ok grep -Fq 'persist-credentials: false' "$WORKFLOW" "trusted checkout never persists the workflow token"
ok grep -Fq 'run: bash scripts/run-trusted-pr-sanitation.sh' "$WORKFLOW" "trusted workflow invokes only its base runner"
# The workflow is a deliberately small security boundary. The digest closes
# alternate YAML spellings such as quoted keys, flow mappings, anchors, and
# aliases that text-only step counts cannot interpret safely.
is "$(file_sha256 "$WORKFLOW")" \
    "2d54052e13e715e6353ca9cee405a41e88c6b4f5dbe94e69ff4558a806953f44" \
    "trusted workflow matches the exact reviewed definition"
ok workflow_has_no_writable_permissions "$WORKFLOW" "trusted workflow grants no writable permission"
is "$(grep -Ec '^[[:space:]]*(-[[:space:]]*)?uses:' "$WORKFLOW")" \
    "1" "trusted workflow has exactly one action step"
is "$(grep -Ec '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]+actions/checkout@' "$WORKFLOW")" \
    "1" "trusted workflow has exactly one checkout"
is "$(grep -Fc 'run: bash scripts/run-trusted-pr-sanitation.sh' "$WORKFLOW")" \
    "1" "trusted workflow invokes its base runner exactly once"
is "$(grep -Ec '^[[:space:]]*(-[[:space:]]*)?run:' "$WORKFLOW")" \
    "1" "trusted workflow executes exactly one shell step"
ok bash -c '! grep -Fq "scripts/tests/" "$1"' _ "$WORKFLOW" "trusted workflow executes no unprotected regression dependency"
ok bash -c '! grep -Eq "statuses: write|checks: write" "$1"' _ "$WORKFLOW" "trusted workflow grants no explicit status or check write permission"
ok bash -c '! grep -Fq "allow-unsafe-pr-checkout" "$1"' _ "$WORKFLOW" "trusted workflow never opts into a candidate checkout"

printf '1..%d\n' "$tests"
if ((failures)); then
    exit 1
fi
