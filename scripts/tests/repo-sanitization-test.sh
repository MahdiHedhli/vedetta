#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
check="$script_dir/../check-repo-sanitization.sh"
source_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

new_repo() {
  name="$1"
  repo="$tmp/$name"
  mkdir -p "$repo/specs/999-sanitize/contracts/fixtures"
  git -C "$repo" init -q
  git -C "$repo" config user.name "Vedetta sanitation test"
  git -C "$repo" config user.email "sanitation-test@vedetta.example"
  printf '%s\n' '{"ip":"192.0.2.8","ipv6":"2001:db8::8","mac":"00:00:5E:00:53:2A","host":"placeholder.local","fqdn":"router.local.example"}' \
    > "$repo/specs/999-sanitize/contracts/fixtures/clean.json"
}

assert_failure() {
  name="$1"
  expected_path="$2"
  shift 2

  set +e
  failure_output="$("$check" "$@" 2>&1)"
  status=$?
  set -e

  # A policy rejection is exit 1 and includes the stable failure marker plus
  # the offending repository path. Exit 2 (argument error), a traceback, or
  # any unrelated non-zero status must never masquerade as a passing guard.
  if [ "$status" -eq 0 ]; then
    printf 'FAIL: sanitation accepted %s\n' "$name" >&2
    exit 1
  fi
  if [ "$status" -ne 1 ]; then
    printf 'FAIL: sanitation check for %s exited %s instead of policy status 1\n%s\n' \
      "$name" "$status" "$failure_output" >&2
    exit 1
  fi
  case "$failure_output" in
    *"Repository sanitation check FAILED:"*) ;;
    *)
      printf 'FAIL: sanitation check for %s omitted the failure marker\n%s\n' \
        "$name" "$failure_output" >&2
      exit 1
      ;;
  esac
  case "$failure_output" in
    *"$expected_path"*) ;;
    *)
      printf 'FAIL: sanitation check for %s omitted path %s\n%s\n' \
        "$name" "$expected_path" "$failure_output" >&2
      exit 1
      ;;
  esac
}

expect_failure() {
  name="$1"
  path="$2"
  contents="$3"
  new_repo "$name"
  mkdir -p "$(dirname -- "$repo/$path")"
  printf '%s\n' "$contents" > "$repo/$path"
  git -C "$repo" add -f .
  assert_failure "$name" "$path" "$repo"
}

expect_redacted_path_failure() {
  name="$1"
  path="$2"
  contents="$3"
  new_repo "$name"
  mkdir -p "$(dirname -- "$repo/$path")"
  printf '%s\n' "$contents" > "$repo/$path"
  git -C "$repo" add -f .
  assert_failure "$name" 'tracked-path#' "$repo"
  if printf '%s' "$failure_output" | grep -F "$path" >/dev/null; then
    printf 'FAIL: sanitation diagnostics disclosed identifier-bearing path %s\n%s\n' \
      "$path" "$failure_output" >&2
    exit 1
  fi
}

expect_success() {
  name="$1"
  path="$2"
  contents="$3"
  new_repo "$name"
  mkdir -p "$(dirname -- "$repo/$path")"
  printf '%s\n' "$contents" > "$repo/$path"
  git -C "$repo" add -f .
  if ! success_output="$("$check" "$repo" 2>&1)"; then
    printf 'FAIL: sanitation rejected %s\n%s\n' "$name" "$success_output" >&2
    exit 1
  fi
}

expect_file_success() {
  name="$1"
  path="$2"
  source="$3"
  new_repo "$name"
  mkdir -p "$(dirname -- "$repo/$path")"
  cp "$source" "$repo/$path"
  git -C "$repo" add -f .
  if ! success_output="$("$check" "$repo" 2>&1)"; then
    printf 'FAIL: sanitation rejected %s\n%s\n' "$name" "$success_output" >&2
    exit 1
  fi
}

expect_fast_failure() {
  name="$1"
  path="$2"
  contents="$3"
  max_milliseconds="$4"
  new_repo "$name"
  mkdir -p "$(dirname -- "$repo/$path")"
  printf '%s\n' "$contents" > "$repo/$path"
  git -C "$repo" add -f .
  started="$(python3 -c 'import time; print(time.monotonic_ns())')"
  assert_failure "$name" "$path" "$repo"
  finished="$(python3 -c 'import time; print(time.monotonic_ns())')"
  elapsed_milliseconds="$(( (finished - started) / 1000000 ))"
  if [ "$elapsed_milliseconds" -gt "$max_milliseconds" ]; then
    printf 'FAIL: sanitation took %sms for %s (limit %sms)\n' \
      "$elapsed_milliseconds" "$name" "$max_milliseconds" >&2
    exit 1
  fi
}

assert_generated_fast_failure() {
  name="$1"
  path="$2"
  max_milliseconds="$3"
  shift 3
  started="$(python3 -c 'import time; print(time.monotonic_ns())')"
  assert_failure "$name" "$path" "$@"
  finished="$(python3 -c 'import time; print(time.monotonic_ns())')"
  elapsed_milliseconds="$(( (finished - started) / 1000000 ))"
  if [ "$elapsed_milliseconds" -gt "$max_milliseconds" ]; then
    printf 'FAIL: sanitation took %sms for %s (limit %sms)\n' \
      "$elapsed_milliseconds" "$name" "$max_milliseconds" >&2
    exit 1
  fi
}

assert_generated_fast_success() {
  name="$1"
  max_milliseconds="$2"
  shift 2
  started="$(python3 -c 'import time; print(time.monotonic_ns())')"
  if ! success_output="$("$check" "$@" 2>&1)"; then
    printf 'FAIL: sanitation rejected %s\n%s\n' "$name" "$success_output" >&2
    exit 1
  fi
  finished="$(python3 -c 'import time; print(time.monotonic_ns())')"
  elapsed_milliseconds="$(( (finished - started) / 1000000 ))"
  if [ "$elapsed_milliseconds" -gt "$max_milliseconds" ]; then
    printf 'FAIL: sanitation took %sms for %s (limit %sms)\n' \
      "$elapsed_milliseconds" "$name" "$max_milliseconds" >&2
    exit 1
  fi
}

new_repo clean
git -C "$repo" add -f .
"$check" "$repo" >/dev/null

new_repo nul-operational-script
mkdir -p "$repo/scripts"
printf '#!/usr/bin/env bash\nprintf safe\0; printf hidden\n' >"$repo/scripts/hidden.sh"
chmod +x "$repo/scripts/hidden.sh"
git -C "$repo" add -f .
assert_failure nul-operational-script scripts/hidden.sh "$repo"

new_repo nul-extensionless-executable
mkdir -p "$repo/scripts"
printf '#!/usr/bin/env bash\nprintf safe\0; printf hidden\n' >"$repo/scripts/hidden"
chmod +x "$repo/scripts/hidden"
git -C "$repo" add -f .
assert_failure nul-extensionless-executable scripts/hidden "$repo"

new_repo nul-sourced-shell-script
mkdir -p "$repo/scripts"
printf 'printf safe\0; printf hidden\n' >"$repo/scripts/hidden.bash"
git -C "$repo" add -f .
assert_failure nul-sourced-shell-script scripts/hidden.bash "$repo"

new_repo nul-sourced-extensionless-helper
mkdir -p "$repo/scripts/lib"
printf 'printf safe\0; printf hidden\n' >"$repo/scripts/lib/runtime-helper"
git -C "$repo" add -f .
assert_failure nul-sourced-extensionless-helper scripts/lib/runtime-helper "$repo"

new_repo recognized-binary-media
mkdir -p "$repo/site/assets"
cp "$source_root/site/assets/og-image.png" "$repo/site/assets/og-image.png"
git -C "$repo" add -f .
"$check" "$repo" >/dev/null

new_repo binary-media-outside-assets
mkdir -p "$repo/scripts/lib"
cp "$source_root/site/assets/og-image.png" "$repo/scripts/lib/disguised.png"
git -C "$repo" add -f .
assert_failure binary-media-outside-assets scripts/lib/disguised.png "$repo"

new_repo invalid-binary-media-magic
mkdir -p "$repo/site/assets"
printf '#!/usr/bin/env bash\nprintf visible\0; printf hidden\n' >"$repo/site/assets/disguised.png"
git -C "$repo" add -f .
assert_failure invalid-binary-media-magic site/assets/disguised.png "$repo"

new_repo valid-magic-binary-polyglot
mkdir -p "$repo/site/assets"
printf '\211PNG\r\n\032\n\nprintf visible\0; printf hidden\n' >"$repo/site/assets/polyglot.png"
git -C "$repo" add -f .
assert_failure valid-magic-binary-polyglot site/assets/polyglot.png "$repo"

new_repo changed-reviewed-binary-media
mkdir -p "$repo/site/assets"
cp "$source_root/site/assets/og-image.png" "$repo/site/assets/og-image.png"
printf 'changed' >>"$repo/site/assets/og-image.png"
git -C "$repo" add -f .
assert_failure changed-reviewed-binary-media site/assets/og-image.png "$repo"

new_repo ascii-replacement-reviewed-media
mkdir -p "$repo/site/assets"
printf '#!/usr/bin/env bash\nprintf hidden\n' >"$repo/site/assets/og-image.png"
git -C "$repo" add -f .
assert_failure ascii-replacement-reviewed-media site/assets/og-image.png "$repo"

new_repo new-ascii-media
mkdir -p "$repo/site/assets"
printf '#!/usr/bin/env bash\nprintf hidden\n' >"$repo/site/assets/new.png"
git -C "$repo" add -f .
assert_failure new-ascii-media site/assets/new.png "$repo"

new_repo ascii-media-outside-assets
mkdir -p "$repo/scripts/lib"
printf '#!/usr/bin/env bash\nprintf hidden\n' >"$repo/scripts/lib/helper.png"
git -C "$repo" add -f .
assert_failure ascii-media-outside-assets scripts/lib/helper.png "$repo"

new_repo executable-reviewed-media
mkdir -p "$repo/site/assets"
cp "$source_root/site/assets/og-image.png" "$repo/site/assets/og-image.png"
chmod +x "$repo/site/assets/og-image.png"
git -C "$repo" add -f .
assert_failure executable-reviewed-media site/assets/og-image.png "$repo"

private_identifier='192.168.44.9'
expect_failure private-ip specs/999-sanitize/contracts/fixtures/leak.json "{\"ip\":\"$private_identifier\"}"
case "$failure_output" in
  *"$private_identifier"*)
    printf 'FAIL: sanitation diagnostics disclosed a rejected identifier\n%s\n' "$failure_output" >&2
    exit 1
    ;;
esac
expect_failure private-ipv6 specs/999-sanitize/contracts/fixtures/leak.json '{"ip":"fd12:3456:789a::9"}'
case "$failure_output" in
  *'fd12:3456:789a::9'*)
    printf 'FAIL: sanitation diagnostics disclosed a rejected IPv6 identifier\n%s\n' "$failure_output" >&2
    exit 1
    ;;
esac
expect_failure invalid-ip specs/999-sanitize/contracts/fixtures/leak.json '{"ip":"192.168.1.999"}'
expect_failure device-mac specs/999-sanitize/contracts/fixtures/leak.json '{"mac":"02:11:22:33:44:55"}'
case "$failure_output" in
  *'02:11:22:33:44:55'*)
    printf 'FAIL: sanitation diagnostics disclosed a rejected MAC identifier\n%s\n' "$failure_output" >&2
    exit 1
    ;;
esac
expect_failure cisco-mac testdata/leak.json '{"mac":"0211.2233.4455"}'
expect_failure compact-mac testdata/leak.json '{"mac":"021122334455"}'
expect_failure local-host specs/999-sanitize/contracts/fixtures/leak.json '{"host":"family-nas.local"}'
case "$failure_output" in
  *'family-nas.local'*)
    printf 'FAIL: sanitation diagnostics disclosed a rejected hostname\n%s\n' "$failure_output" >&2
    exit 1
    ;;
esac
expect_failure local-host-trailing-dot testdata/leak.json '{"host":"family-nas.local."}'
expect_failure home-arpa-host testdata/leak.json '{"host":"family-nas.home.arpa"}'
expect_failure single-label-host testdata/leak.json '{"host":"family-nas"}'
expect_failure private-suffix-host testdata/leak.json '{"host":"family-nas.corp"}'
expect_failure partial-percent-host testdata/leak.json '{"host":"family-nas%"}'
expect_failure partial-angle-host testdata/leak.json '{"host":"family<n>"}'
expect_failure placeholder-substring testdata/leak.json '{"host":"family-placeholder-real.local"}'
expect_failure mdns-instance-host corpus/facts.json '{"notes":"Living-Room-TV._googlecast._tcp.local"}'
expect_failure prefixed-placeholder-host corpus/facts.json '{"notes":"secret.nas-placeholder-01.local"}'
expect_failure nested-placeholder-host corpus/facts.json '{"notes":"a.placeholder.local"}'
expect_failure unicode-local-host corpus/facts.json '{"notes":"café.local"}'
expect_failure unicode-local-host-escaped corpus/facts.json '{"notes":"caf\u00e9.local"}'
expect_failure unicode-cjk-local-host corpus/facts.json '{"notes":"家庭.local"}'
expect_failure unicode-emoji-local-host corpus/facts.json '{"notes":"💻.local"}'
expect_failure unicode-mdns-instance corpus/facts.json '{"notes":"café._googlecast._tcp.local"}'
expect_redacted_path_failure unicode-local-path 'corpus/café.local.json' '{}'
expect_redacted_path_failure mdns-instance-path 'corpus/Living-Room-TV._googlecast._tcp.local.json' '{}'
for idna_dot in '。' '．' '｡'; do
  dot_id="$(printf %s "$idna_dot" | od -An -tx1 | tr -d ' ')"
  expect_failure "idna-dot-content-$dot_id" corpus/facts.json \
    "{\"notes\":\"family-nas${idna_dot}local\"}"
  expect_redacted_path_failure "idna-dot-path-$dot_id" \
    "corpus/family-nas${idna_dot}local.json" '{}'
done
expect_success reserved-suffix testdata/clean.json '{"host":"router.local.example"}'
expect_success mdns-service testdata/clean.json '{"mdns_service":"_googlecast._tcp.local"}'
expect_success placeholder-local-service testdata/clean.json '{"notes":"placeholder.local"}'
expect_success full-host-template testdata/clean.json '{"host":"${HOSTNAME}"}'
expect_failure database data/lab.sqlite 'not a real database'
expect_failure sqlite3-wal data/lab.sqlite3-wal 'not a real database sidecar'
expect_failure sqlite3-shm data/lab.sqlite3-shm 'not a real database sidecar'
expect_failure db-journal data/lab.db-journal 'not a real rollback journal'
expect_failure sqlite-journal data/lab.sqlite-journal 'not a real rollback journal'
expect_failure sqlite3-journal data/lab.sqlite3-journal 'not a real rollback journal'
expect_failure wrapped-sqlite3-journal data/lab.sqlite3-journal.enc 'not a real wrapped rollback journal'
for extension in db3 s3db sl3; do
  expect_failure "database-$extension" "data/lab.$extension" 'not a real database'
  for sidecar in wal shm journal; do
    expect_failure "database-${extension}-${sidecar}" "data/lab.${extension}-${sidecar}" 'not a real database sidecar'
  done
  expect_failure "wrapped-${extension}-journal" "data/lab.${extension}-journal.enc" 'not a real wrapped sidecar'
done
for backup_name in lab.db3~ lab.s3db~ lab.sl3~ lab.db3-wal~ lab.sqlite3~ lab.sqlite3-journal~ notes.txt~; do
  expect_failure "tilde-backup-${backup_name//[^[:alnum:]]/_}" "notes/$backup_name" 'synthetic backup content'
done
expect_failure capture capture.pcap 'not a real capture'
expect_redacted_path_failure compact-mac-capture 021122334455.pcap 'not a real capture'
expect_failure compressed-capture capture.pcap.gz 'not a real compressed capture'
expect_failure compressed-eventlog windows.evtx.gz 'not a real compressed event log'
expect_failure zip-inventory inventory.zip 'not a real archive'
expect_failure tarball corpus.tar.gz 'not a real archive'
expect_failure wrapped-zip inventory.zip.enc 'not a real wrapped archive'
expect_failure wrapped-tarball corpus.tar.gz.gpg 'not a real wrapped archive'
for extension in ndjson jsonl nmap gnmap etl evtx dmp; do
  expect_failure "bare-$extension" "artifact.$extension" 'not a real artifact'
  expect_failure "compressed-$extension" "artifact.$extension.gz" 'not a real compressed artifact'
done
expect_failure raw-log notes/session.log 'not a real log'
expect_failure rotated-log notes/session.log.1 'not a real rotated log'
expect_failure suffixed-log notes/session.log.old 'not a real suffixed log'
expect_failure lab-path lab/readme.txt 'private lab note'
expect_failure env-file .env.production 'TOKEN=placeholder'
expect_failure envrc-file .envrc 'TOKEN=placeholder'
expect_failure uppercase-env-example .ENV.EXAMPLE 'TOKEN=placeholder'
expect_failure suffix-env prod.env 'TOKEN=placeholder'
expect_failure nested-suffix-env config/backend.env 'TOKEN=placeholder'
expect_failure nested-env-example-path .env.example/secret.txt 'TOKEN=placeholder'
expect_redacted_path_failure layered-env config/prod.env.local 'TOKEN=placeholder'
expect_failure layered-env-production config/backend.env.production 'TOKEN=placeholder'
expect_success default-example-cidr .env.example 'VEDETTA_SCAN_CIDR=192.168.1.0/24'
expect_failure environment-example-leak .env.example 'VEDETTA_SCAN_CIDR=192.168.77.0/24'
expect_failure nested-environment-example frontend/.env.example 'HOST=family-nas.local'
expect_redacted_path_failure hostname-layered-env-example family-nas.local.env.example 'TOKEN=placeholder'
expect_redacted_path_failure hostname-layered-env-production family-nas.local.env.production 'TOKEN=placeholder'
expect_redacted_path_failure prefixed-env-host .env.family-nas.local 'TOKEN=placeholder'
expect_redacted_path_failure prefixed-env-home .env.router.home.arpa 'TOKEN=placeholder'
expect_redacted_path_failure prefixed-env-mac .env.021122334455 'TOKEN=placeholder'
for ignorecase in false true; do
  for dotenv_path in .env.example .ENV .ENV.EXAMPLE prod.ENV prod.ENV.LOCAL; do
    if ! git -C "$source_root" -c core.ignorecase="$ignorecase" \
      check-ignore -q --no-index "$dotenv_path"; then
      printf 'FAIL: .gitignore exposes dotenv path %s with core.ignorecase=%s\n' \
        "$dotenv_path" "$ignorecase" >&2
      exit 1
    fi
  done
done
if ! git -C "$source_root" ls-files --error-unmatch .env.example >/dev/null; then
  printf 'FAIL: the reviewed root .env.example is no longer tracked\n' >&2
  exit 1
fi
expect_failure ipv4-trailing-dot testdata/leak.txt '10.1.2.3.'
expect_failure ipv4-dot-prefix testdata/leak.txt 'router.192.168.77.9'
expect_failure private-ip-in-version corpus/device_models.json '{"firmware_version":"v1.192.168.77.9"}'
expect_failure private-prefix-in-version corpus/device_models.json '{"firmware_version":"10.1.2.3.4"}'
expect_failure deploy-host-leak scripts/deploy.sh 'VEDETTA_DEPLOY_HOST=family-nas.local'
expect_success deploy-host-template scripts/deploy.sh 'DEPLOY_HOST="${VEDETTA_DEPLOY_HOST:?Set the deployment host}"'
expect_failure root-corpus corpus/devices.json '{"ip":"192.168.77.9"}'
expect_failure nested-data backend/internal/store/data/devices.json '{"ip":"192.168.77.9"}'
expect_failure nested-dat-data backend/internal/store/data/devices.dat '{"ip":"192.168.77.9"}'
expect_failure nested-source-data backend/internal/store/data/devices.py 'device_ip = "192.168.77.9"'
expect_failure fixture-markdown specs/999-sanitize/contracts/fixtures/leak.md 'Observed family-nas.local at 192.168.77.9.'
expect_failure nested-source-exemption threat-network/internal/corpus/testdata/devices.go 'const deviceIP = "192.168.77.9"'
expect_failure future-corpus-seed threat-network/internal/corpus/seeds.go 'package corpus; const deviceIP = "192.168.77.9"'
expect_failure canonical-production-source threat-network/internal/corpus/canonical.go 'package corpus; const deviceIP = "192.168.77.9"'
expect_success direct-corpus-source threat-network/internal/corpus/privacy_test.go 'const rejectedIP = "192.168.77.9"'
expect_failure singular-fixture fixture/devices.bin '192.168.77.9'
expect_failure singular-sample sample/devices.bin '192.168.77.9'
expect_failure hyphen-test-data test-data/devices.bin '192.168.77.9'
expect_failure underscore-test-data test_data/devices.bin '192.168.77.9'
expect_failure versioned-export-path export-2026/devices.bin '192.168.77.9'
expect_failure versioned-inventory-path inventory-2026/devices.bin '192.168.77.9'
for data_path in \
  fixture-2026 fixtures_v2 sample-2026 test-data-v2 corpus-v2 corpora dataset-v2 data-v2 \
  demo-data-v2 lab-2026 captures-v2 exports-2026 inventories-2026 backups-v2 \
  dumps-v2 scans-v2 pcaps-v2 packet-captures-v2; do
  expect_failure "versioned-path-${data_path}" "$data_path/devices.bin" '192.168.77.9'
done
expect_failure versioned-corpus-source corpus-v2/seeds.go 'package corpus; const deviceIP = "192.168.77.9"'
for data_path in backups dumps scans pcaps packet-captures; do
  expect_failure "plural-path-${data_path}" "$data_path/devices.bin" '192.168.77.9'
done
for ignored_path in \
  lab-prod/hosts.bin labs-dev/hosts.go .local-prod/hosts.go capture-old/hosts.bin \
  backup-prod/tool.go export-prod/tool.go inventory-prod/seeds.go inventories_dev/seeds.bin; do
  expect_failure "broad-ignored-${ignored_path//[^[:alnum:]]/_}" "$ignored_path" 'synthetic content'
done
for local_path in \
  logs-prod/session.txt logs.archive/session.txt internal/config.txt private-dev/note.txt \
  .aws-old/config .gcp_test/config .terraform.backup/state .docker-local/config \
  analysis-notes-v2/note.txt agent-scratch_tmp/note.txt scratch.archive/note.txt \
  .codex-old/state .claude_tmp/state .cursor.backup/state; do
  expect_failure "local-only-${local_path//[^[:alnum:]]/_}" "$local_path" 'synthetic local-only content'
done
expect_success dependency-cache-control node_modules/example/index.js 'export const fixture = true;'
expect_success build-cache-control build/cache/readme.md 'synthetic build cache documentation'
expect_failure archive-parent-path export.zip/nested/devices.bin '192.168.77.9'
expect_failure nested-inventory-dat backend/inventory/devices.dat '{"ip":"192.168.77.9"}'
expect_failure opaque-inventory-dat device_inventory.dat '{"ip":"192.168.77.9"}'
expect_failure opaque-scan-data scan.bin '192.168.77.9'
expect_success product-scan-source sensor/internal/scan.go 'package sensor'
expect_success operational-backup-script scripts/backup.sh '#!/usr/bin/env bash'
expect_failure root-inventory inventory.json '{"ip":"192.168.77.9"}'
expect_success uuidv4-corpus-path corpus/3c5e7a9b-2d4f-4a6c-8e0b-1f3a5c7e9b0d.json '{}'
expect_redacted_path_failure uuidv1-node-path corpus/6ba7b810-9dad-11d1-80b4-021122334455.json '{}'
expect_failure plural-root-inventory inventories.json '{"name":"Living Room TV"}'
expect_failure inventory-friendly-name device_inventory.json '{"name":"Living Room TV"}'
expect_failure csv-inventory device_inventory.csv 'host,ip,mac
family-nas,192.168.77.9,02:11:22:33:44:55'
expect_failure inventory-map-key corpus/device_inventory.json '{"family-nas":{"model":"NAS"}}'
expect_failure inventory-wrapped-map-key corpus/device_inventory.json '{"devices":{"family-nas":{"model":"NAS"}}}'
expect_failure inventory-yaml-key corpus/device_inventory.yaml 'family-nas:'
expect_failure inventory-txt-host corpus/device_inventory.txt 'family-nas'
expect_failure nested-inventory-txt-host inventory/hosts.txt 'family-nas'
expect_success ordinary-corpus-narrative corpus/notes.txt 'ordinary narrative text without identifiers'
expect_failure inventory-csv-host-header corpus/device_inventory.csv $'family-nas\nfoo'
expect_failure inventory-csv-secondary-host-header corpus/device_inventory.csv $'model,family-nas\nRouter,foo'
expect_success inventory-json-schema corpus/device_inventory.json \
  '{"devices":[{"vendor":"Example","model":"Router 1","hostname":"router.example","ports":[80,443],"services":["http"]}]}'
expect_success inventory-csv-schema corpus/device_inventory.csv $'vendor,model,hostname\nExample,Router 1,router.example'
expect_failure nested-inventory-name corpus/device.inventory.json \
  '{"devices":[{"metadata":{"name":"family-nas"}}]}'
expect_failure nested-inventory-notes corpus/device.fingerprints.json \
  '{"devices":[{"metadata":{"notes":"family-nas"}}]}'
expect_failure inventory-notes-prose-identifier corpus/device.fingerprints.json \
  '{"devices":[{"notes":"observed family-nas during review"}]}'
expect_failure inventory-labeled-comment corpus/device.data.json \
  '{"devices":[{"comments":"hostname=family-nas"}]}'
expect_success inventory-note-prose corpus/device.inventory.json \
  '{"devices":[{"notes":"reviewed synthetic fixture without identifiers"}]}'
expect_failure inventory-txt-name-dot-path corpus/device.inventory.txt 'name: family-nas'
expect_failure inventory-txt-comment-dot-path corpus/device.fingerprints.txt 'comment: family-nas'
expect_failure inventory-csv-dot-path corpus/device.data.csv $'name,model\nfamily-nas,Router 1'
expect_success risk-shaped-source-control docs/device.inventory.md 'Device inventory design documentation.'
expect_failure nmap-xml scan.xml '<nmaprun><host><address addr="192.168.77.9"/><hostnames><hostname name="family-nas"/></hostnames></host></nmaprun>'
expect_failure nmap-compact-mac scan.xml '<nmaprun><host><address addr="021122334455" addrtype="mac"/></host></nmaprun>'
expect_failure xml-encoded-host scan.xml '<nmaprun><hostname name="family&#45;nas&#46;local"/></nmaprun>'
expect_failure xml-encoded-ip scan.xml '<nmaprun><ip>&#49;92&#46;168&#46;77&#46;9</ip></nmaprun>'
expect_failure xml-doctype-safe scan.xml '<!DOCTYPE nmaprun [<!ENTITY x "192.168.77.9">]><nmaprun><ip>&x;</ip></nmaprun>'
expect_failure json-unicode-ip corpus/facts.json '{"notes":"\u0031\u0039\u0032.\u0031\u0036\u0038.77.9"}'
expect_failure json-unicode-ipv6 corpus/facts.json '{"notes":"fd12\u003a3456\u003a789a\u003a\u003a9"}'
expect_failure json-array-unicode-ip corpus/facts.json '["\u0031\u0039\u0032.\u0031\u0036\u0038.77.9"]'
expect_failure json-array-unicode-host corpus/facts.json '["family-nas\u002elocal"]'
expect_failure json-unicode-ip-key corpus/facts.json '{"\u0031\u0039\u0032.\u0031\u0036\u0038.77.9":{}}'
expect_failure json-unicode-host-key corpus/facts.json '{"family-nas\u002elocal":{}}'
expect_failure malformed-json-eav corpus/facts.json '{"attribute":"mac","value":"021122334455",}'
expect_failure duplicate-json-key corpus/facts.json '{"attribute":"hostname","attribute":"version","value":"family-nas"}'
expect_failure normalized-duplicate-json-key corpus/facts.json '{"attribute":"hostname","Attribute":"version","value":"family-nas"}'
expect_failure json-typed-array corpus/facts.json '{"hostname":["family-nas"]}'
expect_failure json-eav-typed-array corpus/facts.json '{"attribute":"mac","value":["021122","334455"]}'
expect_failure json-relational-typed-array corpus/facts.json '{"id_type":"hostname","id_value":["family-nas"]}'
expect_failure json-generic-compact-mac corpus/facts.json '{"identifier":"021122334455"}'
expect_failure json-embedded-compact-mac corpus/facts.json '{"notes":"observed MAC 021122334455 today"}'
expect_failure json-wrapped-compact-mac corpus/facts.json '{"identifier":"[021122334455]"}'
expect_failure json-uuidv1-node-mac corpus/facts.json '{"id":"6ba7b810-9dad-11d1-80b4-021122334455"}'
expect_failure json-compact-mac-in-key corpus/facts.json '{"a021122334455":"x"}'
for mac_value in mac021122334455 bssid021122334455 mac0x021122334455 0x021122334455; do
  expect_failure "json-contextual-mac-$mac_value" corpus/facts.json "{\"notes\":\"$mac_value\"}"
done
for mac_value in \
  'macAddress: 021122334455' 'mac_address=021122334455' 'macAddr: 021122334455' \
  'sourceMac: 021122334455' 'source_mac_address=021122334455' \
  'deviceMac: 021122334455' 'device_mac=021122334455' 'hardwareAddress: 021122334455'; do
  expect_failure "json-labeled-mac-${mac_value//[^[:alnum:]]/_}" \
    corpus/facts.json "{\"notes\":\"$mac_value\"}"
done
expect_redacted_path_failure contextual-mac-path corpus/mac021122334455.json '{}'
expect_redacted_path_failure hex-compact-mac-path corpus/0x021122334455.json '{}'
expect_success contextual-documentation-mac corpus/facts.json '{"notes":"mac00005e00532a"}'
expect_success long-hex-hash corpus/facts.json \
  '{"notes":"sha256:021122334455abcdef021122334455abcdef021122334455abcdef021122334455abcd"}'
expect_success sha256-structured-map-key corpus/facts.json \
  '{"021122334455abcd021122334455abcd021122334455abcd021122334455abcd":{"model":"synthetic"}}'
expect_failure labeled-mac-structured-map-key corpus/facts.json '{"device-021122334455":{"model":"synthetic"}}'
expect_success long-prefixed-hex corpus/facts.json '{"notes":"0x021122334455abcdef"}'
expect_failure json-decimal-ip corpus/facts.json '{"ip":3232235777}'
expect_failure json-decimal-mac corpus/facts.json '{"mac":2272611484757}'
expect_failure json-camel-host corpus/facts.json '{"deviceHostname":"family-nas"}'
expect_failure json-kebab-host corpus/facts.json '{"device-hostname":"family-nas"}'
expect_failure json-camel-decimal-ip corpus/facts.json '{"ipAddress":3232235777}'
expect_failure json-camel-decimal-mac corpus/facts.json '{"macAddress":2272611484757}'
for mac_key in macAddr macaddr MACAddr MacAddr HWAddr hwAddr HWAddress; do
  expect_failure "json-alias-mac-${mac_key}" corpus/facts.json "{\"$mac_key\":\"021122334455\"}"
done
expect_failure json-macaddr-decimal corpus/facts.json '{"macaddr":2272611484757}'
for ip_key in IPv4Address ipV4Address; do
  expect_failure "json-alias-ip-${ip_key}" corpus/facts.json "{\"$ip_key\":\"192.168.77.9\"}"
done
expect_failure json-alias-mdns-name corpus/facts.json '{"mDNSName":"family-nas"}'
expect_success json-alias-documentation-values corpus/facts.json \
  '{"HWAddr":"00005e00532a","IPv4Address":"192.0.2.8","mDNSName":"router.example"}'
expect_failure json-camel-relational-host corpus/facts.json '{"idType":"hostname","idValue":"family-nas"}'
expect_failure json-canonical-duplicate-key corpus/facts.json '{"deviceName":"router.example","device_name":"family-nas"}'
expect_failure csv-display-host-header corpus/facts.csv $'Device Name\nfamily-nas'
expect_failure csv-camel-relational-host corpus/facts.csv $'ID Type,ID Value\nhostname,family-nas'
expect_failure csv-canonical-duplicate-header corpus/facts.csv $'deviceName,device_name\nrouter.example,family-nas'
expect_failure xml-camel-host corpus/facts.xml '<facts deviceHostname="family-nas"/>'
expect_failure xml-acronym-mac corpus/facts.xml '<facts HWAddr="021122334455"/>'
expect_failure xml-canonical-duplicate-attribute corpus/facts.xml \
  '<facts deviceName="router.example" device_name="family-nas"/>'
expect_success json-camel-firmware-version corpus/facts.json '{"firmwareVersion":"1.0.11.216"}'
expect_failure json-composite-host-space corpus/facts.json '{"hostname":"family-nas attacker.example"}'
expect_failure json-composite-host-slash corpus/facts.json '{"hostname":"family-nas/attacker.example"}'
expect_failure json-composite-host-empty-label corpus/facts.json '{"hostname":"family-nas..example"}'
for mac_value in 0211-2233-4455 '02 11 22 33 44 55' 02_11_22_33_44_55 021122-334455; do
  expect_failure "json-alternate-mac-${mac_value//[^[:alnum:]]/_}" corpus/facts.json "{\"mac\":\"$mac_value\"}"
done
expect_failure yaml-relational-host corpus/facts.yaml $'attribute: hostname\nvalue: family-nas'
expect_failure text-relational-host corpus/facts.txt $'attribute=hostname\nvalue=family-nas'
expect_failure ini-relational-host corpus/facts.ini $'id_type=hostname\nid_value=family-nas'
expect_failure yaml-folded-host corpus/facts.yaml $'hostname: >-\n  family-nas'
expect_failure toml-array-mac corpus/facts.toml 'mac = ["021122334455"]'
expect_failure ini-continuation-host corpus/facts.ini $'hostname =\n family-nas'
expect_failure yaml-flow-host corpus/facts.yaml '{hostname: family-nas}'
expect_failure yaml-flow-relational-host corpus/facts.yaml '{attribute: hostname, value: family-nas}'
expect_failure yaml-scalar-sequence-host corpus/facts.yaml '- family-nas'
expect_failure toml-inline-table-host corpus/facts.toml 'fact = { hostname = "family-nas" }'
expect_failure ini-bare-host corpus/facts.ini 'family-nas'
expect_failure yaml-display-key-host corpus/device.inventory.yaml 'Device Hostname: family-nas'
expect_failure yaml-dotted-key-host corpus/device.inventory.yaml 'device.hostname: family-nas'
expect_failure yaml-canonical-duplicate corpus/device.inventory.yaml \
  $'device.hostname: router.example\ndeviceHostname: router.example'
expect_success yaml-list-record-scope corpus/device.inventory.yaml \
  $'devices:\n  - name: placeholder\n    notes: reviewed fixture one\n  - name: placeholder\n    notes: reviewed fixture two'
expect_success ini-section-scope corpus/device.inventory.ini \
  $'[device]\nDevice Hostname=router.example\n[asset]\ndevice.hostname=router.example'
expect_failure ini-duplicate-section corpus/device.inventory.ini \
  $'[device]\nhostname=router.example\n[Device]\nhostname=router.example'
expect_success txt-blank-record-scope corpus/device.inventory.txt \
  $'name: placeholder\n\nname: placeholder'
expect_success yaml-block-script-scope .github/workflows/example.yml \
  $'jobs:\n  check:\n    steps:\n      - name: synthetic\n        run: |\n          base="$ONE"\n          base="$TWO"'
new_repo generic-line-limit
mkdir -p "$repo/corpus"
awk 'BEGIN { for (i = 0; i < 100001; i++) print "a=x" }' > "$repo/corpus/facts.txt"
git -C "$repo" add -f .
assert_failure generic-line-limit corpus/facts.txt "$repo"
for separator_case in cr line-separator; do
  new_repo "generic-line-limit-$separator_case"
  mkdir -p "$repo/corpus"
  python3 - "$repo/corpus/facts.txt" "$separator_case" <<'PY'
from pathlib import Path
import sys

separator = "\r" if sys.argv[2] == "cr" else "\u2028"
Path(sys.argv[1]).write_text(("a=x" + separator) * 100_001, encoding="utf-8")
PY
  git -C "$repo" add -f .
  assert_generated_fast_failure "generic-line-limit-$separator_case" corpus/facts.txt 3000 "$repo"
done

for separator_case in lf cr line-separator; do
  new_repo "json-lines-limit-$separator_case"
  jsonl_path='specs/001-unifi-log-ingestion/corpus/expected/limit.expected.json'
  mkdir -p "$(dirname -- "$repo/$jsonl_path")"
  python3 - "$repo/$jsonl_path" "$separator_case" <<'PY'
from pathlib import Path
import sys

separators = {"lf": "\n", "cr": "\r", "line-separator": "\u2028"}
Path(sys.argv[1]).write_text(("0" + separators[sys.argv[2]]) * 100_001, encoding="utf-8")
PY
  git -C "$repo" add -f .
  assert_generated_fast_failure "json-lines-limit-$separator_case" "$jsonl_path" 3000 "$repo"
done

new_repo json-lines-shared-value-limit
jsonl_path='specs/001-unifi-log-ingestion/corpus/expected/shared.expected.json'
mkdir -p "$(dirname -- "$repo/$jsonl_path")"
python3 - "$repo/$jsonl_path" <<'PY'
from pathlib import Path
import sys

# Exercise the cross-document value budget without making runner speed depend
# on fifty thousand separate json.loads calls. Each line contributes 50,001
# values (the list plus 50,000 scalars), so two individually valid documents
# exceed the shared 100,000-value cap by two.
line = "[" + ",".join(["0"] * 50_000) + "]\n"
Path(sys.argv[1]).write_text(line * 2, encoding="utf-8")
PY
git -C "$repo" add -f .
assert_generated_fast_failure json-lines-shared-value-limit "$jsonl_path" 3000 "$repo"

expect_success reviewed-json-lines specs/001-unifi-log-ingestion/corpus/expected/example.expected.json $'{"ip":"192.0.2.8"}\n{"mac":"00:00:5E:00:53:2A"}'
expect_success reviewed-empty-json-lines specs/001-unifi-log-ingestion/corpus/expected/empty.expected.json ''
expect_failure malformed-reviewed-json-line specs/001-unifi-log-ingestion/corpus/expected/example.expected.json $'{"ip":"192.0.2.8"}\n{"attribute":"mac","value":"021122334455",}'

allowlist_path='threat-network/internal/store/data/allowlist.txt'
expect_success public-domain-allowlist "$allowlist_path" $'# public domains\ngoogle.com\none.one'
expect_failure allowlist-bare-host "$allowlist_path" 'family-nas'
expect_failure allowlist-local-host "$allowlist_path" 'router.local'
expect_failure allowlist-url "$allowlist_path" 'https://google.com/'
expect_failure allowlist-wildcard "$allowlist_path" '*.google.com'
expect_failure allowlist-uppercase "$allowlist_path" 'Google.com'
expect_failure allowlist-trailing-dot "$allowlist_path" 'google.com.'
expect_failure allowlist-duplicate "$allowlist_path" $'google.com\ngoogle.com'
expect_failure json-domain-percent-pattern corpus/facts.json '{"domain":"fp-%"}'
expect_failure yaml-domain-underscore-pattern corpus/facts.yaml 'domain: device_name.example'
expect_success json-canonical-public-domain corpus/facts.json '{"domain":"router.example.com"}'

for log_fixture in cef iptables noise wan_drops; do
  expect_file_success "unifi-log-$log_fixture" \
    "specs/001-unifi-log-ingestion/corpus/inputs/$log_fixture.log" \
    "$script_dir/../../specs/001-unifi-log-ingestion/corpus/inputs/$log_fixture.log"
done
unifi_log_path='specs/001-unifi-log-ingestion/corpus/inputs/leak.log'
expect_failure unifi-header-host "$unifi_log_path" \
  '<134>Jul  3 10:21:00 family-nas CEF:0|Ubiquiti|UniFi|1|x|x|1|msg=ok'
expect_failure unifi-dhcpack-host "$unifi_log_path" \
  '<30>Jul  3 10:21:10 gateway-placeholder dnsmasq-dhcp[1]: DHCPACK(br0) 192.0.2.45 00:00:5E:00:53:0A family-nas'
for host_field in deviceHostname deviceHostName clientHostName serverHostName hostname dhost shost dvchost; do
  expect_failure "unifi-cef-host-$host_field" "$unifi_log_path" \
    "<134>Jul  3 10:21:00 gateway-placeholder CEF:0|Ubiquiti|UniFi|1|x|x|1|$host_field=family-nas"
done
expect_failure unifi-malformed-pri "$unifi_log_path" '<134>not a complete RFC3164 line'
expect_failure unifi-unknown-noise "$unifi_log_path" 'family-nas emitted a non-syslog line'

expect_failure xml-numeric-ip corpus/facts.xml '<facts><ip>&#49;92&#46;168&#46;77&#46;9</ip></facts>'
expect_failure xml-eav-compact-mac corpus/facts.xml '<facts><attribute>mac</attribute><value>021122334455</value></facts>'
expect_failure xml-eav-hostname corpus/facts.xml '<facts><attribute>hostname</attribute><value>family-nas</value></facts>'
expect_failure xml-multi-eav-hostname corpus/facts.xml '<facts><fact><attribute>ip</attribute><value>192.0.2.8</value></fact><fact><attribute>hostname</attribute><value>family-nas</value></fact></facts>'
expect_failure xml-attribute-eav-hostname corpus/facts.xml '<facts><fact attribute="hostname" value="family-nas"/></facts>'
expect_failure xml-quoted-delimiter-ip corpus/facts.xml '<facts><fact note=">" ip="&#49;92&#46;168&#46;77&#46;9"/></facts>'
expect_failure xml-unclosed-quote corpus/facts.xml '<facts><fact attribute="hostname value="family-nas"/></facts>'
expect_failure xml-unquoted-attribute corpus/facts.xml '<facts><fact attribute="hostname" value=family-nas/></facts>'
expect_failure xml-normalized-duplicate-attribute corpus/facts.xml '<facts><fact attribute="hostname" Attribute="version" value="family-nas"/></facts>'
expect_failure xml-mismatched-close corpus/facts.xml '<facts><hostname>family-nas</host></facts>'
expect_failure xml-unknown-entity corpus/facts.xml '<facts><fact attribute="hostname" value="family&custom;nas"/></facts>'
expect_success xml-quoted-greater-than corpus/facts.xml '<facts><fact note=">" attribute="hostname" value="router.example"/></facts>'
expect_failure xml-reverse-eav-hostname corpus/facts.xml '<facts><fact><value>family-nas</value><attribute>hostname</attribute></fact></facts>'
expect_failure xml-nested-eav-hostname corpus/facts.xml '<facts><fact><attribute>hostname</attribute><wrapper><value>family-nas</value></wrapper></fact></facts>'
expect_success xml-nested-firmware-version corpus/facts.xml '<facts><firmware_version>1.0.11.216</firmware_version></facts>'
expect_success xml-attribute-eav-version corpus/facts.xml '<facts><fact attribute="hardware_revision" value="1.0.11.216"/></facts>'
expect_success xml-id-version-attributes corpus/facts.xml '<facts><fact idType="firmware_version" idValue="1.0.11.216"/></facts>'
expect_success xml-id-version-children corpus/facts.xml '<facts><fact><idType>firmware_version</idType><idValue>1.0.11.216</idValue></fact></facts>'
expect_success xml-escaped-version-children corpus/facts.xml \
  '<facts><fact><idType>firmware_version</idType><idValue>1&#46;0&#46;11&#46;216</idValue></fact></facts>'
expect_success xml-escaped-version-eav-children corpus/facts.xml \
  '<facts><fact><attribute>firmware_version</attribute><value>1&#46;0&#46;11&#46;216</value></fact></facts>'
expect_failure xml-escaped-version-occurrence-scope corpus/facts.xml \
  '<facts><firmware_version>1.0.11.216</firmware_version><value>1&#46;0&#46;11&#46;216</value></facts>'
expect_failure xml-escaped-version-cross-record-scope corpus/facts.xml \
  '<facts><fact><attribute>firmware_version</attribute><value>1.0.11.216</value></fact><fact><value>1&#46;0&#46;11&#46;216</value></fact></facts>'
expect_failure xml-escaped-unmapped-relational-value corpus/facts.xml \
  '<facts><fact><attribute>firmware_version</attribute><value>1.0.11.216</value><idValue>192&#46;168&#46;77&#46;9</idValue></fact></facts>'
expect_failure xml-escaped-unmapped-relational-attribute corpus/facts.xml \
  '<facts><fact attribute="firmware_version" value="1.0.11.216" idValue="192&#46;168&#46;77&#46;9"/></facts>'
expect_failure xml-relation-plus-split-private-ip corpus/facts.xml \
  '<facts><attribute>firmware_version</attribute><value>1.0.11.216</value><x>192.</x><y>168.77.9</y></facts>'
expect_failure xml-relation-plus-split-mac corpus/facts.xml \
  '<facts><attribute>firmware_version</attribute><value>1.0.11.216</value><x>02:11:22:</x><y>33:44:55</y></facts>'
expect_failure xml-relation-plus-split-hostname corpus/facts.xml \
  '<facts><attribute>firmware_version</attribute><value>1.0.11.216</value><x>family-</x><y>nas.local</y></facts>'
expect_failure xml-typed-version-fragment-plus-sibling-ip corpus/facts.xml \
  '<facts><firmware_version>192.</firmware_version><x>168.77.9</x></facts>'
expect_failure xml-eav-version-fragment-plus-sibling-ip corpus/facts.xml \
  '<facts><attribute>firmware_version</attribute><value>192.</value><x>168.77.9</x></facts>'
expect_failure xml-typed-version-fragment-plus-sibling-mac corpus/facts.xml \
  '<facts><firmware_version>02:11:22:</firmware_version><x>33:44:55</x></facts>'
expect_success xml-version-range-children corpus/facts.xml \
  '<fact><attribute>firmware_version</attribute><value>1.0.11.216</value><value_end>2.0.12.217</value_end></fact>'
expect_success xml-repeated-version-values corpus/facts.xml \
  '<fact><attribute>firmware_version</attribute><value>1.0.11.216</value><value>1.0.11.216</value></fact>'
expect_success xml-reversed-version-relation corpus/facts.xml \
  '<fact><value>1.0.11.216</value><attribute>firmware_version</attribute></fact>'
expect_failure xml-nested-version-prefix-plus-sibling-ip corpus/facts.xml \
  '<facts><wrapper><firmware_version>192.168</firmware_version></wrapper><x>.77.9</x></facts>'
expect_failure xml-nested-eav-version-prefix-plus-sibling-ip corpus/facts.xml \
  '<facts><wrapper><attribute>firmware_version</attribute><value>192.168</value></wrapper><x>.77.9</x></facts>'
expect_failure xml-nested-version-prefix-plus-sibling-cisco-mac corpus/facts.xml \
  '<facts><wrapper><firmware_version>0211.2233</firmware_version></wrapper><x>.4455</x></facts>'
expect_failure xml-nested-version-prefix-plus-sibling-local corpus/facts.xml \
  '<facts><wrapper><firmware_version>1.2</firmware_version></wrapper><x>.local</x></facts>'
expect_success xml-nested-version-prefix-whitespace-separated corpus/facts.xml \
  '<facts><wrapper><firmware_version>192.168</firmware_version></wrapper> <x>.77.9</x></facts>'
expect_success xml-adjacent-safe-version-occurrences corpus/facts.xml \
  '<facts><firmware_version>1.2</firmware_version><firmware_version>1.0.11.216</firmware_version></facts>'
expect_success xml-nested-adjacent-safe-version-occurrences corpus/facts.xml \
  '<facts><wrapper><firmware_version>1.2</firmware_version></wrapper><wrapper><firmware_version>1.0.11.216</firmware_version></wrapper></facts>'
expect_success xml-adjacent-eav-version-range corpus/facts.xml \
  '<fact><attribute>firmware_version</attribute><value>1.2</value><value_end>1.0.11.216</value_end></fact>'
expect_success xml-attribute-version-with-quoted-greater-than corpus/facts.xml \
  '<facts><fact note=">" attribute="firmware_version" value="1.0.11.216"/></facts>'
expect_success xml-reversed-attribute-version-with-quoted-greater-than corpus/facts.xml \
  '<facts><fact value="1.0.11.216" note=">" attribute="firmware_version"/></facts>'
expect_success xml-multiple-version-relations corpus/facts.xml \
  '<facts><fact><attribute>firmware_version</attribute><value>1.0.11.216</value></fact><fact><attribute>hardware_revision</attribute><value>2.0.12.217</value></fact></facts>'
expect_failure xml-id-private-version corpus/facts.xml '<facts><fact><idType>firmware_version</idType><idValue>192.168.77.9</idValue></fact></facts>'
expect_failure xml-unbound-prefix corpus/facts.xml '<x:facts/>'
expect_failure xml-bogus-declaration corpus/facts.xml '<?xml hostname="family-nas"?><facts/>'
expect_failure xml-embedded-compact-mac corpus/facts.xml '<facts><note>observed MAC 021122334455 today</note></facts>'
expect_failure xml-mixed-ip corpus/facts.xml '<facts><note>192.<b/>168.77.9</note></facts>'
expect_failure xml-mixed-mac corpus/facts.xml '<facts><note>0211<b/>22334455</note></facts>'
expect_failure xml-mixed-host corpus/facts.xml '<facts><note>family-nas.lo<b/>cal</note></facts>'
expect_failure xml-child-split-ip corpus/facts.xml '<facts><note><span>192.</span><span>168.77.9</span></note></facts>'
expect_failure xml-child-split-mac corpus/facts.xml '<facts><note><span>0211</span><span>22334455</span></note></facts>'
expect_failure xml-child-split-host corpus/facts.xml '<facts><note><span>family-nas.lo</span><span>cal</span></note></facts>'
expect_failure xml-ambiguous-discriminator corpus/facts.xml '<facts><fact><attribute>hostname</attribute><attribute>version</attribute><value>family-nas</value></fact></facts>'
expect_failure xml-compact-mac-tag corpus/facts.xml '<facts><mac_021122334455/></facts>'
expect_failure xml-compact-mac-attribute corpus/facts.xml '<facts a021122334455="x"/>'
long_dotted_text="$(awk 'BEGIN { for (i = 0; i < 20000; i++) printf "a." }')"
expect_success bounded-local-name-scan corpus/facts.txt "$long_dotted_text"
long_local_suffix="$(awk 'BEGIN { for (i = 0; i < 120; i++) printf "a." }')family-nas.local"
expect_failure long-dotted-local-suffix corpus/facts.json "{\"notes\":\"$long_local_suffix\"}"
malformed_xml="$(awk 'BEGIN { for (i = 0; i < 50000; i++) printf "<a" }')"
expect_failure bounded-malformed-xml corpus/facts.xml "$malformed_xml"
new_repo xml-raw-nul
mkdir -p "$repo/corpus"
printf '<facts>\0</facts>' > "$repo/corpus/facts.xml"
git -C "$repo" add -f .
assert_failure xml-raw-nul corpus/facts.xml "$repo"
expect_failure xml-cdata-mac corpus/facts.xml '<facts><mac><![CDATA[021122334455]]></mac></facts>'
expect_failure xml-cdata-host corpus/facts.xml '<facts><hostname><![CDATA[family-nas]]></hostname></facts>'
expect_failure xml-encoded-doctype corpus/facts.xml '<!DOCTYPE facts [<!ENTITY x "&#49;92&#46;168&#46;77&#46;9">]><facts><ip>&x;</ip></facts>'
expect_failure nmap-shape-only scan.xml '<nmaprun><runstats><finished/></runstats></nmaprun>'
expect_failure sql-dump production.sql 'INSERT INTO devices VALUES ("192.168.77.9");'
expect_failure migration-sql siem/migrations/999_leak.sql 'INSERT INTO devices VALUES ("192.168.77.9");'
for legacy_sql in \
  009_event_type_encrypted_dns.sql 018_device_correlation.sql \
  019_relax_segment_check.sql 020_repair_correlation_fks.sql \
  025_asset_centered_findings.sql; do
  expect_file_success "legacy-sql-${legacy_sql%.sql}" "siem/migrations/$legacy_sql" \
    "$source_root/siem/migrations/$legacy_sql"
done
for changed_legacy_sql in 018_device_correlation.sql 019_relax_segment_check.sql; do
  new_repo "changed-legacy-${changed_legacy_sql%.sql}"
  mkdir -p "$repo/siem/migrations"
  cp "$source_root/siem/migrations/$changed_legacy_sql" "$repo/siem/migrations/$changed_legacy_sql"
  printf '\n-- digest-changing review required\n' >> "$repo/siem/migrations/$changed_legacy_sql"
  git -C "$repo" add -f .
  assert_failure "changed legacy SQL" "siem/migrations/$changed_legacy_sql" "$repo"
done
expect_file_success db-health-read-only scripts/db-health.sql "$source_root/scripts/db-health.sql"
new_repo db-health-parameter
mkdir -p "$repo/scripts"
cp "$source_root/scripts/db-health.sql" "$repo/scripts/db-health.sql"
printf '\n.parameter set @hostname family-nas\nUPDATE devices SET hostname=@hostname;\n' >> "$repo/scripts/db-health.sql"
git -C "$repo" add -f .
assert_failure db-health-parameter scripts/db-health.sql "$repo"
expect_failure db-health-writable-cte-update scripts/db-health.sql \
  'WITH pending AS (SELECT 1) UPDATE counters SET total=0;'
expect_failure db-health-writable-cte-delete scripts/db-health.sql \
  'WITH pending AS (SELECT 1) DELETE FROM counters;'
expect_failure db-health-numeric-parameter scripts/db-health.sql 'SELECT :1;'
expect_file_success seed-static-fixture scripts/seed-snr-validation.sql "$source_root/scripts/seed-snr-validation.sql"
expect_failure seed-insert-select scripts/seed-snr-validation.sql \
  "INSERT INTO events(source_ip) SELECT payload FROM staging;"
expect_failure seed-writable-cte-update scripts/seed-snr-validation.sql \
  'WITH pending AS (SELECT 1) UPDATE counters SET total=0;'
expect_failure seed-writable-cte-delete scripts/seed-snr-validation.sql \
  'WITH pending AS (SELECT 1) DELETE FROM counters;'
expect_failure seed-numeric-parameter scripts/seed-snr-validation.sql \
  'INSERT INTO counters(total) VALUES(@1);'
expect_failure sql-numeric-parameter-colon siem/migrations/999_numeric_parameter_colon.sql \
  'SELECT :1;'
expect_failure sql-numeric-parameter-at siem/migrations/999_numeric_parameter_at.sql \
  'SELECT @1;'
expect_failure sql-numeric-parameter-dollar siem/migrations/999_numeric_parameter_dollar.sql \
  'SELECT $1;'
expect_failure sql-temp-payload-laundering siem/migrations/999_temp_payload.sql \
  "CREATE TEMP TABLE payload(x TEXT); INSERT INTO payload(x) VALUES('family-nas'); INSERT INTO devices(hostname) SELECT x FROM payload;"
expect_failure sql-split-fragment-laundering siem/migrations/999_split_payload.sql \
  "CREATE TEMP TABLE payload(a TEXT,b TEXT); INSERT INTO payload(a,b) VALUES('family','-nas'); INSERT INTO devices(hostname) SELECT a||b FROM payload;"
expect_failure version-shaped-ip corpus/device_models.json '{"ip":"1.0.11.216"}'
expect_success firmware-version corpus/device_models.json '{"firmware_version":"1.0.11.216"}'
expect_success vendor-firmware-version corpus/device_models.json '{"firmware_version":"V1.0.11.216_2.1.216"}'
expect_success three-digit-firmware-version corpus/device_models.json '{"firmware_version":"1.2.3.998"}'
expect_success max-three-digit-firmware-version corpus/device_models.json '{"firmware_version":"1.2.3.999"}'
for invalid_private_version in 192.168.77.999 10.1.2.999 172.16.5.999 169.254.1.999; do
  expect_failure "invalid-private-version-${invalid_private_version//./_}" \
    corpus/device_models.json "{\"firmware_version\":\"$invalid_private_version\"}"
done
expect_success non-private-vendor-version corpus/device_models.json '{"firmware_version":"999.1.2.3"}'
expect_success five-part-public-firmware-version corpus/device_models.json '{"firmware_version":"v1.2.3.4.5"}'
expect_failure private-version corpus/device_models.json '{"version":"192.168.1.1"}'
expect_failure cgnat-version corpus/device_models.json '{"version":"100.64.0.1"}'
expect_failure version-occurrence-scope corpus/device_models.json '{"version":"1.0.11.216","notes":"1.0.11.216"}'
expect_failure escaped-version-occurrence-scope corpus/device_models.json \
  '{"firmware_version":"1.0.11.216","value":"\u0031.0.11.216"}'
expect_failure escaped-version-reversed-scope corpus/device_models.json \
  '{"value":"\u0031\u002e\u0030\u002e\u0031\u0031\u002e\u0032\u0031\u0036","firmware_version":"1.0.11.216"}'
expect_failure escaped-version-nested-scope corpus/device_models.json \
  '{"device":{"firmware_version":"1.0.11.216"},"value":"\u0031.0.11.216"}'
expect_failure escaped-version-cross-object-scope corpus/device_models.json \
  '{"facts":[{"attribute":"firmware_version","value":"1.0.11.216"},{"value":"\u0031.0.11.216"}]}'
expect_failure escaped-version-unmapped-relational-key corpus/device_models.json \
  '{"attribute":"firmware_version","value":"1.0.11.216","idValue":"\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039"}'
expect_success json-version-relation-with-braces-in-sibling corpus/device_models.json \
  '{"attribute":"firmware_version","notes":"{}","value":"1.0.11.216"}'
expect_success json-reversed-version-relation-with-braces corpus/device_models.json \
  '{"value":"1.0.11.216","notes":"{}","attribute":"firmware_version"}'
expect_failure json-equal-unmapped-version-occurrence corpus/device_models.json \
  '{"attribute":"firmware_version","value":"1.0.11.216","notes":"1.0.11.216"}'
expect_failure json-cross-object-version-relation corpus/device_models.json \
  '{"fact":{"attribute":"firmware_version"},"value":"1.0.11.216"}'
expect_failure yaml-escaped-untyped-private-ip corpus/device_models.yaml \
  'notes: "\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039"'
expect_failure toml-escaped-untyped-private-ip corpus/device_models.toml \
  'notes = "\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039"'
expect_failure yaml-escaped-untyped-private-ip-global config/facts.yaml \
  'notes: "\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039"'
expect_failure yaml-plain-escaped-private-ip-global config/facts.yaml \
  'notes: \u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039'
expect_failure yaml-comment-escaped-private-ip-global config/facts.yaml \
  '# \u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039'
expect_failure yaml-inline-comment-escaped-private-ip-global config/facts.yaml \
  'notes: safe # \u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039'
expect_failure yaml-plain-apostrophe-before-escaped-private-ip config/facts.yaml \
  $'description: don\'t\nnotes: "\\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039"\nfooter: \''
expect_failure toml-escaped-untyped-private-ip-global config/facts.toml \
  'notes = "\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039"'
expect_failure toml-invalid-prefix-before-literal-escaped-private-ip config/facts.toml \
  $'description = abc \'\'\'\nnotes = "\\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039"\nfooter = \'\'\''
expect_failure toml-comma-prefix-before-literal-escaped-private-ip config/facts.toml \
  $'description = abc, \'\'\'\nnotes = "\\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039"\nfooter = \'\'\''
expect_failure toml-repeated-equals-before-literal-escaped-private-ip config/facts.toml \
  $'description = nope = \'\'\'\nnotes = "\\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039"\nfooter = \'\'\''
expect_failure toml-comment-literal-escaped-private-ip config/facts.toml \
  '# '\''\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039'\'''
expect_failure toml-inline-comment-literal-escaped-private-ip config/facts.toml \
  'notes = '\''safe'\'' # '\''\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039'\'''
expect_success toml-inline-comment-apostrophe config/facts.toml \
  "notes = 'safe' # don't"
expect_failure yaml-escaped-line-continuation config/facts.yaml \
  $'notes: "192.168.\\\n  77.9"'
expect_failure toml-escaped-line-continuation config/facts.toml \
  $'notes = """192.168.\\\n77.9"""'
expect_failure yaml-tagged-escaped-private-ip config/facts.yaml \
  'notes: !!str "\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039"'
expect_success yaml-github-negation-expression .github/workflows/sanitation.yml \
  'if: ${{ !github.event.deleted }}'
expect_success yaml-github-chained-expressions .github/workflows/sanitation.yml \
  'name: ${{ github.ref }} && ${{ github.sha }}'
expect_success yaml-github-expression-taglike-suffix .github/workflows/sanitation.yml \
  'name: ${{ github.ref }} !important'
expect_success yaml-github-incomplete-expression-in-comment .github/workflows/sanitation.yml \
  'if: success() # literal ${{ in comment'
expect_success yaml-github-incomplete-expression-in-name-comment .github/workflows/sanitation.yml \
  'name: safe # docs use ${{'
expect_success yaml-github-incomplete-expression-in-whole-comment .github/workflows/sanitation.yml \
  '# GitHub syntax starts ${{'
expect_success yaml-github-incomplete-expression-after-double-quoted-value .github/workflows/sanitation.yml \
  'name: "safe" # literal ${{'
expect_success yaml-github-incomplete-expression-after-single-quoted-value .github/workflows/sanitation.yml \
  "name: 'safe' # literal \${{"
expect_success yaml-github-incomplete-expression-after-quoted-expression .github/workflows/sanitation.yml \
  'name: "${{ github.ref }}" # docs ${{'
expect_failure yaml-github-incomplete-expression-in-quoted-value .github/workflows/sanitation.yml \
  'name: "literal ${{"'
expect_failure yaml-github-incomplete-expression-in-quoted-value-before-comment .github/workflows/sanitation.yml \
  'name: "literal ${{" # trailing comment'
expect_failure yaml-github-escaped-private-ip-in-comment .github/workflows/sanitation.yml \
  'if: success() # \u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039'
expect_success yaml-github-multiline-negation-expression .github/workflows/sanitation.yml \
  $'if: ${{\n  !cancelled()\n  && success()\n  }}'
expect_success yaml-github-multiline-expression-after-operator .github/workflows/sanitation.yml \
  $'if: ${{ github.event_name == \'push\' &&\n  !cancelled() }}'
expect_success yaml-github-multiline-condition-without-braces .github/workflows/sanitation.yml \
  $'if: success() &&\n  !cancelled()'
expect_success yaml-github-multiline-comparison-line .github/workflows/sanitation.yml \
  $'if: ${{\n  github.event_name == \'push\'\n  && !cancelled()\n  }}'
expect_success yaml-github-multiline-colon-without-space .github/workflows/sanitation.yml \
  $'if: ${{ contains(github.ref, \'refs:heads\') &&\n  !cancelled() }}'
expect_success yaml-github-sequence-multiline-condition .github/workflows/sanitation.yml \
  $'- if: success() &&\n    !cancelled()\n  name: safe-step'
expect_success yaml-github-indented-sequence-multiline-condition .github/workflows/sanitation.yml \
  $'  - if: success() &&\n      !cancelled()\n    name: safe-step'
expect_failure yaml-github-expression-escaped-private-ip .github/workflows/sanitation.yml \
  'if: ${{ "\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039" }}'
expect_failure yaml-github-multiline-escaped-private-ip .github/workflows/sanitation.yml \
  $'if: ${{\n  "\\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039"\n  }}'
expect_failure yaml-github-unclosed-multiline-expression .github/workflows/sanitation.yml \
  $'if: ${{\n  !cancelled()\nname: next-node'
expect_failure yaml-github-unclosed-sibling-expression .github/workflows/sanitation.yml \
  $'if: ${{ success() }} && ${{\n  !cancelled()'
expect_failure yaml-github-unclosed-single-line-expression .github/workflows/sanitation.yml \
  'if: ${{ success()'
expect_failure yaml-github-multiline-structured-continuation .github/workflows/sanitation.yml \
  $'if: success() &&\n  nested: !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-github-colon-terminated-condition-tag .github/workflows/sanitation.yml \
  $'if: success(): !!binary MTkyLjE2OC43Ny45\n  !cancelled()'
expect_failure yaml-github-continuation-colon-terminated-tag .github/workflows/sanitation.yml \
  $'if: success() &&\n  success(): !!binary MTkyLjE2OC43Ny45\n  !cancelled()'
expect_failure yaml-github-literal-quote-does-not-mask-colon .github/workflows/sanitation.yml \
  $'if: foo \'x: !!binary MTkyLjE2OC43Ny45\' &&\n  !cancelled()'
expect_failure yaml-github-braced-expression-does-not-mask-colon .github/workflows/sanitation.yml \
  $'if: ${{ contains(github.ref, \'refs: heads\') &&\n  !cancelled() }}'
expect_failure yaml-github-sequence-peer-tag .github/workflows/sanitation.yml \
  $'- if: success() &&\n    !cancelled()\n  notes: !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-github-sequence-shallow-tag .github/workflows/sanitation.yml \
  $'- if: success() &&\n  !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-github-compact-invalid-sequence-tag .github/workflows/sanitation.yml \
  $'-if: success() &&\n  !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-github-comment-ended-condition-tag .github/workflows/sanitation.yml \
  $'if: success() && # scalar ends here\n  !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-github-tabbed-continuation-tag .github/workflows/sanitation.yml \
  $'if: success() &&\n\t!!binary MTkyLjE2OC43Ny45'
expect_failure yaml-github-sequence-tabbed-continuation-tag .github/workflows/sanitation.yml \
  $'- if: success() &&\n\t!!binary MTkyLjE2OC43Ny45'
expect_failure yaml-github-tabbed-key-and-continuation-tag .github/workflows/sanitation.yml \
  $'\tif: success() &&\n\t\t!!binary MTkyLjE2OC43Ny45'
expect_failure yaml-github-path-tag-before-expression .github/workflows/sanitation.yml \
  'notes: !!str ${{ github.ref }}'
expect_failure yaml-github-path-flow-delimited-tag .github/workflows/sanitation.yml \
  'notes: [${{ github.ref }}, !!binary MTkyLjE2OC43Ny45]'
expect_failure yaml-github-path-real-binary-tag .github/workflows/sanitation.yml \
  'notes: !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-binary-tag-private-ip config/facts.yaml \
  'notes: !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-binary-tag-quoted-private-ip config/facts.yaml \
  'notes: !!binary "MTkyLjE2OC43Ny45"'
expect_failure yaml-verbatim-binary-tag-private-ip config/facts.yaml \
  'notes: !<tag:yaml.org,2002:binary> MTkyLjE2OC43Ny45'
expect_failure yaml-custom-tag-private-ip config/facts.yaml \
  'notes: !custom MTkyLjE2OC43Ny45'
expect_failure yaml-anchor-binary-tag-private-ip config/facts.yaml \
  'notes: &secret !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-numeric-anchor-binary-tag-private-ip config/facts.yaml \
  'notes: &1 !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-punctuation-anchor-binary-tag-private-ip config/facts.yaml \
  'notes: &.x !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-punctuation-alias-private-ip config/facts.yaml \
  'notes: *.x'
expect_failure yaml-explicit-key-binary-tag config/workflow.yaml \
  $'? !!binary MTkyLjE2OC43Ny45\n: safe'
expect_failure yaml-document-binary-tag config/workflow.yaml \
  '--- !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-tag-directive-custom-tag config/workflow.yaml \
  $'%TAG !e! tag:example.com,2026:\n--- !e!foo MTkyLjE2OC43Ny45'
expect_failure yaml-sequence-explicit-key-binary-tag config/workflow.yaml \
  $'- ? !!binary MTkyLjE2OC43Ny45\n  : safe'
expect_failure yaml-sequence-explicit-key-anchor-binary-tag config/workflow.yaml \
  $'- ? &1 !!binary MTkyLjE2OC43Ny45\n  : safe'
expect_failure yaml-bom-root-binary-tag config/workflow.yaml \
  $'\xEF\xBB\xBF!!binary MTkyLjE2OC43Ny45'
expect_failure yaml-bom-document-binary-tag config/workflow.yaml \
  $'\xEF\xBB\xBF--- !!binary MTkyLjE2OC43Ny45'
expect_failure yaml-bom-explicit-key-binary-tag config/workflow.yaml \
  $'\xEF\xBB\xBF? !!binary MTkyLjE2OC43Ny45\n: safe'
expect_failure yaml-flow-escaped-private-ip config/facts.yaml \
  'notes: ["\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039"]'
expect_failure toml-array-escaped-private-ip config/facts.toml \
  'notes = ["\u0031\u0039\u0032\u002e\u0031\u0036\u0038\u002e\u0037\u0037\u002e\u0039"]'
expect_failure yaml-multiline-flow-escaped-private-ip config/facts.yaml \
  $'notes: [\n  "\n  \\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039\n  "\n]'
expect_failure yaml-block-scalar-escaped-private-ip config/facts.yaml \
  $'notes: |\n  \\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039'
expect_failure yaml-folded-scalar-escaped-private-ip config/facts.yaml \
  $'notes: >-\n  \\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039'
expect_success yaml-block-scalar-backslash config/workflow.yaml \
  $'run: |\n  printf "%s\\n" safe'
expect_success yaml-plain-shell-bang config/workflow.yaml \
  'run: if ! grep -q foo; then echo safe; fi'
expect_success yaml-plain-ampersand-word config/workflow.yaml \
  'run: echo foo &background'
expect_success yaml-plain-important config/workflow.yaml \
  'description: wow !important'
expect_success yaml-plain-glob config/workflow.yaml \
  'glob: echo *files'
expect_success yaml-single-literal-escape config/workflow.yaml \
  "notes: '\\u0031 literal'"
expect_success toml-single-literal-escape config/workflow.toml \
  "notes = '\\u0031 literal'"
expect_failure yaml-single-literal-escaped-private-ip config/facts.yaml \
  "notes: '\\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039'"
expect_failure toml-single-literal-escaped-private-ip config/facts.toml \
  "notes = '\\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039'"
expect_failure toml-triple-literal-escaped-private-ip config/facts.toml \
  "notes = '''\\u0031\\u0039\\u0032\\u002e\\u0031\\u0036\\u0038\\u002e\\u0037\\u0037\\u002e\\u0039'''"
expect_file_success gitleaks-toml .gitleaks.toml "$source_root/.gitleaks.toml"
expect_success json-version-fact corpus/device_models.json '{"attribute":"firmware_version","source":"vendor","value":"V1.0.11.216_2.1.216"}'
expect_success json-hardware-revision corpus/device_models.json '{"attribute":"hardware_revision","value":"1.0.11.216"}'
expect_success json-escaped-version-key corpus/device_models.json '{"firmware\u005fversion":"1.0.11.216"}'
expect_success json-escaped-attribute-key corpus/device_models.json '{"attr\u0069bute":"firmware_version","value":"1.0.11.216"}'
expect_success json-escaped-version-value corpus/device_models.json '{"firmware_version":"\u0031.0.11.216"}'
expect_success json-escaped-version-fact-value corpus/device_models.json \
  '{"attribute":"firmware_version","value":"\u0031.0.11.216"}'
expect_success bom-json-hardware-revision corpus/device_models.json $'\xEF\xBB\xBF{"attribute":"hardware_revision","value":"1.0.11.216"}'
expect_success json-version-range corpus/device_models.json '{"attribute":"firmware_version","relation":"range","value":"1.0.0.1","value_end":"1.0.11.216"}'
expect_success json-documentation-eav corpus/facts.json '{"facts":[{"attribute":"mac","value":"00005e00532a"},{"attribute":"hostname","value":"router.example"},{"attribute":"ip","value":"192.0.2.8"}]}'
expect_failure json-private-eav corpus/facts.json '{"facts":[{"attribute":"mac","value":"021122334455"},{"attribute":"hostname","value":"family-nas"},{"attribute":"ip","value":"192.168.77.9"}]}'
expect_failure json-eav-compact-mac corpus/facts.json '{"attribute":"mac","value":"021122334455"}'
expect_failure bom-json-eav-compact-mac corpus/facts.json $'\xEF\xBB\xBF{"attribute":"mac","value":"021122334455"}'
expect_failure json-eav-hostname corpus/facts.json '{"attribute":"hostname","value":"family-nas"}'
expect_failure json-private-version-end corpus/device_models.json '{"attribute":"firmware_version","relation":"range","value":"1.0.0.1","value_end":"192.168.77.9"}'
expect_failure private-json-version-fact corpus/device_models.json '{"attribute":"firmware_version","value":"192.168.1.1"}'
expect_success csv-hardware-revision corpus/device_models.csv $'attribute,value\nhardware_revision,1.0.11.216'
expect_success bom-csv-hardware-revision corpus/device_models.csv $'\xEF\xBB\xBFattribute,value\nhardware_revision,1.0.11.216'
expect_success csv-version-range corpus/device_models.csv $'attribute,relation,value,value_end\nfirmware_version,range,1.0.0.1,1.0.11.216'
expect_success csv-id-version corpus/device_models.csv $'id_type,id_value\nfirmware_version,1.0.11.216'
expect_failure csv-id-private-version corpus/device_models.csv $'id_type,id_value\nfirmware_version,192.168.77.9'
expect_success yaml-id-version corpus/device_models.yaml $'ID Type: firmwareVersion\nID Value: 1.0.11.216'
expect_failure yaml-id-private-version corpus/device_models.yaml $'ID Type: firmwareVersion\nID Value: 192.168.77.9'
expect_success toml-id-version corpus/device_models.toml $'[device]\nid.type = "firmware_version"\nid.value = "1.0.11.216"'
expect_success csv-documentation-eav corpus/facts.csv $'attribute,value\nmac,00005e00532a\nhostname,router.example\nip,192.0.2.8'
expect_failure csv-private-eav corpus/facts.csv $'attribute,value\nmac,021122334455\nhostname,family-nas\nip,192.168.77.9'
expect_failure csv-eav-compact-mac corpus/facts.csv $'attribute,value\nmac,021122334455'
expect_failure bom-csv-eav-compact-mac corpus/facts.csv $'\xEF\xBB\xBFattribute,value\nmac,021122334455'
expect_failure bom-quoted-csv-eav-compact-mac corpus/facts.csv $'\xEF\xBB\xBF"attribute",value\nmac,021122334455'
expect_failure inner-bom-csv-eav-compact-mac corpus/facts.csv $'attribute,value\n\xEF\xBB\xBFmac,021122334455'
expect_failure csv-eav-hostname corpus/facts.csv $'attribute,value\nhostname,family-nas'
expect_failure csv-private-version-end corpus/device_models.csv $'attribute,relation,value,value_end\nfirmware_version,range,1.0.0.1,192.168.77.9'
expect_success csv-multiline-version-range corpus/device_models.csv $'attribute,notes,value,value_end\nhardware_revision,"hello\nworld",1.2.3.998,1.2.3.999'
expect_success csv-empty-optional-value corpus/facts.csv $'attribute,value\nhostname,'
expect_success csv-blank-record corpus/facts.csv $'attribute,value\n\nmac,00005e00532a'
expect_failure csv-generic-compact-mac corpus/facts.csv $'kind,identifier\ndevice,021122334455'
expect_failure csv-prefixed-compact-mac corpus/facts.csv $'kind,identifier\ndevice,prefix-021122334455-suffix'
expect_failure csv-compact-header corpus/facts.csv '021122334455'
expect_failure csv-compact-header-with-columns corpus/facts.csv $'021122334455,name\nsafe,value'
expect_failure csv-semicolon-host corpus/facts.csv $'attribute;value\nhostname;family-nas'
expect_failure csv-semicolon-mac corpus/facts.csv $'attribute;value\nmac;021122334455'
expect_failure csv-pipe-host corpus/facts.csv $'attribute|value\nhostname|family-nas'
expect_failure tsv-pipe-host corpus/facts.tsv $'attribute|value\nhostname|family-nas'
expect_failure tsv-comma-host corpus/facts.tsv $'attribute,value\nhostname,family-nas'

new_repo version-span-performance
mkdir -p "$repo/corpus"
awk 'BEGIN { print "id_type,id_value"; for (i = 0; i < 20000; i++) print "firmware_version,1.2.3.4" }' \
  > "$repo/corpus/device_models.csv"
git -C "$repo" add -f .
assert_generated_fast_success version-span-performance 8000 "$repo"
expect_success sql-firmware-version siem/migrations/999_version.sql "INSERT INTO devices (firmware_version) VALUES ('1.0.11.216');"
expect_success sql-version-fact siem/migrations/999_version_fact.sql "INSERT INTO device_version_facts (attribute, value) VALUES ('firmware_version', '1.0.11.216');"
expect_success sql-hardware-revision siem/migrations/999_hardware.sql "INSERT INTO device_version_facts (attribute, value) VALUES ('hardware_revision', '1.0.11.216');"
expect_success sql-version-range siem/migrations/999_range.sql "INSERT INTO device_version_facts (attribute, relation, value, value_end) VALUES ('firmware_version', 'range', '1.0.0.1', '1.0.11.216');"
expect_success sql-documentation-eav siem/migrations/999_documentation.sql "INSERT INTO facts (attribute, value) VALUES ('mac', '00005e00532a'), ('hostname', 'router.example'), ('ip', '192.0.2.8');"
expect_failure sql-private-eav siem/migrations/999_private_eav.sql "INSERT INTO facts (attribute, value) VALUES ('mac', '021122334455'), ('hostname', 'family-nas'), ('ip', '192.168.77.9');"
expect_failure sql-eav-compact-mac siem/migrations/999_eav_mac.sql "INSERT INTO facts (attribute, value) VALUES ('mac', '021122334455');"
expect_failure sql-eav-hostname siem/migrations/999_eav_host.sql "INSERT INTO facts (attribute, value) VALUES ('hostname', 'family-nas');"
expect_failure sql-private-version-end siem/migrations/999_private_end.sql "INSERT INTO facts (attribute, value, value_end) VALUES ('firmware_version', '1.0.0.1', '192.168.77.9');"
expect_failure sql-compact-identity siem/migrations/999_identity.sql "INSERT INTO devices (mac, hostname) VALUES ('021122334455', 'family-nas');"
expect_failure sql-unkeyed-values siem/migrations/999_unkeyed.sql "INSERT INTO devices VALUES ('021122334455', 'family-nas');"
expect_failure sql-replace-values siem/migrations/999_replace.sql "REPLACE INTO devices (mac, hostname) VALUES ('021122334455', 'family-nas');"
expect_failure sql-eof-values siem/migrations/999_eof.sql "INSERT INTO devices (mac, hostname) VALUES ('021122334455', 'family-nas')"
expect_failure sql-quoted-semicolon siem/migrations/999_semicolon.sql "INSERT INTO devices (notes, mac, hostname) VALUES ('semi;colon', '021122334455', 'family-nas');"
expect_failure sql-table-comment siem/migrations/999_comment.sql "INSERT INTO devices /* reviewed */ (mac, hostname) VALUES ('021122334455', 'family-nas');"
expect_failure sql-blob-mac siem/migrations/999_blob.sql "INSERT INTO devices (mac, hostname) VALUES (X'021122334455', 'family-nas');"
expect_failure sql-ascii-blob-mac siem/migrations/999_ascii_blob.sql "INSERT INTO devices (mac) VALUES (X'303231313232333334343535');"
expect_failure sql-select-identity siem/migrations/999_select.sql "INSERT INTO devices (mac, hostname) SELECT '021122334455', 'family-nas';"
expect_failure sql-update-blob siem/migrations/999_update.sql "UPDATE devices SET mac=X'021122334455', hostname='family-nas';"
expect_failure sql-update-quoted siem/migrations/999_update_quoted.sql "UPDATE devices SET \"mac\"=X'021122334455', [hostname]='family-nas';"
expect_failure sql-update-expression siem/migrations/999_update_expression.sql "UPDATE devices SET mac=CAST(X'021122334455' AS TEXT), hostname=lower('family-nas');"
expect_failure sql-update-eav siem/migrations/999_update_eav.sql "UPDATE facts SET attribute='mac', value=CAST(X'021122334455' AS TEXT);"
expect_failure sql-update-concat siem/migrations/999_update_concat.sql "UPDATE devices SET mac='021122'||'334455';"
expect_failure sql-update-double-concat siem/migrations/999_update_double.sql 'UPDATE devices SET mac="021122"||"334455";'
expect_failure sql-update-eav-concat siem/migrations/999_update_eav_concat.sql "UPDATE facts SET attribute='m'||'ac', value='021122'||'334455';"
expect_failure sql-update-function-concat siem/migrations/999_update_function.sql "UPDATE devices SET mac=lower('021122'||'334455'), ip=lower('192.168.'||'77.9');"
expect_failure sql-update-printf siem/migrations/999_update_printf.sql "UPDATE devices SET mac=printf('%s%s','021122','334455');"
expect_failure sql-update-eav-function siem/migrations/999_update_eav_function.sql "UPDATE facts SET attribute=lower('m'||'ac'), value=lower('021122'||'334455');"
expect_failure sql-update-replace siem/migrations/999_update_replace.sql "UPDATE devices SET mac=replace('021122-334455','-',''), ip=replace('192x168x77x9','x','.');"
expect_failure sql-update-char siem/migrations/999_update_char.sql "UPDATE devices SET mac=char(48,50,49,49,50,50,51,51,52,52,53,53);"
expect_failure sql-update-tuple-identity siem/migrations/999_update_tuple.sql \
  'UPDATE devices SET (hostname, notes)=(SELECT model, notes FROM staging);'
expect_failure sql-update-tuple-relational siem/migrations/999_update_tuple_relational.sql \
  'UPDATE facts SET (id_type, id_value)=(SELECT kind, identifier FROM staging);'
expect_failure sql-update-untyped-nested-comparison siem/migrations/999_update_untyped_nested.sql \
  "UPDATE devices SET notes=(SELECT 'router.example'=hostname);"
expect_failure sql-update-untyped-case-comparison siem/migrations/999_update_untyped_case.sql \
  "UPDATE devices SET notes=CASE WHEN 'router.example'=hostname THEN '' ELSE '' END;"
expect_success sql-update-untyped-structural-copy siem/migrations/999_update_untyped_copy.sql \
  'UPDATE devices SET notes=hostname;'
expect_failure sql-update-reverse-typed-predicate siem/migrations/999_update_reverse_typed.sql \
  "UPDATE devices SET notes='' WHERE 'router.example'=hostname;"
expect_failure sql-update-nested-typed-predicate siem/migrations/999_update_nested_typed.sql \
  "UPDATE devices SET notes='' WHERE EXISTS(SELECT 1 WHERE 'router.example' IS hostname);"
expect_failure sql-update-from-join-typed-predicate siem/migrations/999_update_from_join.sql \
  "UPDATE devices SET notes='' FROM a, b JOIN c ON 'router.example'=b.hostname WHERE devices.id=a.id;"
expect_failure sql-update-order-typed-predicate siem/migrations/999_update_order.sql \
  "UPDATE devices SET notes='' ORDER BY 'router.example'=hostname LIMIT 1;"
expect_failure sql-update-limit-typed-case siem/migrations/999_update_limit.sql \
  "UPDATE devices SET notes='' LIMIT CASE WHEN 'router.example'=hostname THEN 1 ELSE 1 END;"
expect_success sql-update-from-structural-join siem/migrations/999_update_from_copy.sql \
  "UPDATE devices SET notes='' FROM a JOIN b ON a.hostname=b.hostname WHERE devices.id=a.id;"
expect_success sql-update-order-structural siem/migrations/999_update_order_copy.sql \
  "UPDATE devices SET notes='' ORDER BY hostname LIMIT 1;"
expect_failure sql-update-returning-literal siem/migrations/999_update_returning_literal.sql \
  "UPDATE devices SET notes='' RETURNING 'router.example' AS hostname;"
expect_failure sql-update-returning-aggregate siem/migrations/999_update_returning_aggregate.sql \
  "UPDATE devices SET notes='' RETURNING (SELECT group_concat(hostname,'') FROM devices);"
expect_failure sql-update-returning-keyword-literal siem/migrations/999_update_returning_keyword.sql \
  "UPDATE devices SET notes='' RETURNING TRUE AS hostname;"
expect_success sql-update-returning-copy siem/migrations/999_update_returning_copy.sql \
  "UPDATE devices SET notes='' RETURNING coalesce(hostname,'') AS hostname;"
expect_failure sql-insert-select-char siem/migrations/999_insert_select_char.sql "INSERT INTO devices (mac) SELECT char(48,50,49,49,50,50,51,51,52,52,53,53);"
expect_failure sql-insert-select-untyped-nested-comparison siem/migrations/999_insert_untyped_nested.sql \
  "INSERT INTO logs(x) SELECT (SELECT 'router.example'=hostname) FROM devices;"
expect_failure sql-values-untyped-nested-comparison siem/migrations/999_values_untyped_nested.sql \
  "INSERT INTO logs(x) VALUES((SELECT 'router.example'=hostname FROM devices));"
expect_success sql-insert-select-untyped-structural-copy siem/migrations/999_insert_untyped_copy.sql \
  'INSERT INTO logs(x) SELECT hostname FROM devices;'
expect_failure sql-cte-insert-char siem/migrations/999_cte_insert_char.sql "WITH leak(mac) AS (SELECT char(48,50,49,49,50,50,51,51,52,52,53,53)) INSERT INTO devices (mac) SELECT mac FROM leak;"
expect_failure sql-cte-update-char siem/migrations/999_cte_update_char.sql "WITH leak(mac) AS (SELECT char(48,50,49,49,50,50,51,51,52,52,53,53)) UPDATE devices SET mac=(SELECT mac FROM leak);"
expect_failure sql-alias-update-char siem/migrations/999_alias_update_char.sql "UPDATE devices AS d SET mac=char(48,50,49,49,50,50,51,51,52,52,53,53);"
expect_failure sql-bracket-update-char siem/migrations/999_bracket_update_char.sql "UPDATE [devices] SET mac=char(48,50,49,49,50,50,51,51,52,52,53,53);"
expect_failure sql-update-where-eav siem/migrations/999_update_where_eav.sql "UPDATE facts SET value='021122334455' WHERE attribute='mac';"
expect_failure sql-update-where-eav-host siem/migrations/999_update_where_host.sql "UPDATE facts SET value='family-nas' WHERE attribute='hostname';"
expect_success sql-update-where-version siem/migrations/999_update_where_version.sql "UPDATE facts SET value='1.2.3.999' WHERE attribute='hardware_revision';"
expect_success sql-update-parenthesized-where siem/migrations/999_update_parenthesized.sql "UPDATE facts SET value='00005e00532a' WHERE (attribute='mac');"
expect_success sql-update-reverse-where siem/migrations/999_update_reverse.sql "UPDATE facts SET value='00005e00532a' WHERE 'mac'=attribute;"
expect_success sql-update-attribute-overrides-where siem/migrations/999_update_override.sql "UPDATE facts SET attribute='mac', value='00005e00532a' WHERE attribute='hostname';"
expect_failure sql-update-where-or siem/migrations/999_update_where_or.sql "UPDATE facts SET value='family-nas' WHERE attribute='mac' OR 1=1;"
expect_failure sql-update-where-not siem/migrations/999_update_where_not.sql "UPDATE facts SET value='family-nas' WHERE NOT attribute='mac';"
expect_failure sql-update-where-eav-replace siem/migrations/999_update_where_replace.sql "UPDATE facts SET value=replace('021122-334455','-','') WHERE attribute='mac';"
expect_failure sql-trigger-update-replace siem/migrations/999_trigger_replace.sql "CREATE TRIGGER leak AFTER INSERT ON devices BEGIN UPDATE devices SET mac=replace('021122-334455','-',''); END;"
many_sql_literals="UPDATE devices SET mac="
for _index in $(seq 1 4097); do
  if [ "$many_sql_literals" != "UPDATE devices SET mac=" ]; then
    many_sql_literals="${many_sql_literals}||"
  fi
  many_sql_literals="${many_sql_literals}''"
done
expect_failure sql-literal-limit siem/migrations/999_literal_limit.sql "${many_sql_literals};"
unterminated_sql="/*$(awk 'BEGIN { for (i = 0; i < 40000; i++) printf "a/*" }')"
expect_failure sql-unterminated-comment siem/migrations/999_unterminated.sql "$unterminated_sql"
many_boolean_sql="UPDATE facts SET value='router.example' WHERE $(awk 'BEGIN { for (i = 0; i < 50001; i++) printf "x=x AND " }') attribute='hostname';"
expect_failure sql-boolean-limit siem/migrations/999_boolean_limit.sql "$many_boolean_sql"
expect_failure sql-cte-insert siem/migrations/999_cte.sql "WITH leak(mac, hostname) AS (VALUES ('021122334455', 'family-nas')) INSERT INTO devices (mac, hostname) SELECT * FROM leak;"
expect_failure sql-cte-double siem/migrations/999_cte_double.sql 'WITH leak(mac) AS (VALUES ("021122334455")) INSERT INTO devices (mac) SELECT * FROM leak;'
expect_failure sql-cte-update siem/migrations/999_cte_update.sql "WITH leak(mac) AS (VALUES ('021122334455')) UPDATE devices SET mac=(SELECT mac FROM leak);"
expect_failure sql-trigger-update siem/migrations/999_trigger_update.sql "CREATE TRIGGER leak AFTER INSERT ON devices BEGIN UPDATE devices SET \"mac\"=X'021122334455'; END;"
expect_failure sql-subquery-source siem/migrations/999_subquery.sql "INSERT INTO devices(mac) SELECT src.mac FROM (SELECT '021122334455' AS mac) src;"
expect_failure sql-upsert-tail siem/migrations/999_upsert.sql "INSERT INTO devices(hostname) VALUES ('router.example') ON CONFLICT(id) DO UPDATE SET hostname='family-nas';"
expect_failure sql-id-type-pair siem/migrations/999_id_pair.sql "INSERT INTO device_identities(id_type,id_value) VALUES('mac','021122334455');"
expect_failure sql-address-type-pair siem/migrations/999_address_pair.sql "INSERT INTO device_address_history(address_type,address_value) VALUES('mac','021122334455');"
expect_failure sql-field-pair siem/migrations/999_field_pair.sql "INSERT INTO device_signals(field,value) VALUES('hostname','family-nas');"
expect_failure sql-observable-pair siem/migrations/999_observable_pair.sql "INSERT INTO evidence(observable_type,observable_value) VALUES('destination_ip','192.168.77.9');"
expect_failure sql-custom-name siem/migrations/999_custom_name.sql "INSERT INTO devices(custom_name) VALUES('family-nas');"
expect_failure sql-default-host siem/migrations/999_default_host.sql "CREATE TABLE devices(hostname TEXT DEFAULT 'family-nas');"
expect_failure sql-alter-default-host siem/migrations/999_alter_host.sql "ALTER TABLE devices ADD COLUMN hostname TEXT DEFAULT 'family-nas';"
expect_failure sql-where-host siem/migrations/999_where_host.sql "UPDATE devices SET hostname=hostname WHERE hostname='family-nas';"
expect_failure sql-delete-host siem/migrations/999_delete_host.sql "DELETE FROM devices WHERE hostname='family-nas';"
expect_failure sql-view-host siem/migrations/999_view_host.sql "CREATE VIEW leak AS SELECT 'family-nas' AS hostname;"
expect_failure sql-check-mac siem/migrations/999_check_mac.sql "CREATE TABLE devices(mac TEXT CHECK(mac!='021122334455'));"
expect_failure sql-comment-identities siem/migrations/999_comment_ids.sql '-- mac=021122334455 hostname=family-nas'
expect_failure sql-comment-colon-host siem/migrations/999_comment_colon.sql '-- hostname: family-nas'
expect_failure sql-parenthesized-default siem/migrations/999_default_paren.sql "CREATE TABLE devices(hostname TEXT DEFAULT ('family-nas'));"
expect_failure sql-function-default siem/migrations/999_default_function.sql "CREATE TABLE devices(hostname TEXT DEFAULT lower('family-nas'));"
expect_failure sql-function-check siem/migrations/999_check_function.sql "CREATE TABLE devices(hostname TEXT CHECK(lower(hostname)!=lower('family-nas')));"
expect_failure sql-delete-like siem/migrations/999_delete_like.sql "DELETE FROM devices WHERE hostname LIKE 'family-nas';"
expect_failure sql-in-second-value siem/migrations/999_in_second.sql "DELETE FROM devices WHERE hostname IN ('router.example','family-nas');"
expect_failure sql-view-replace siem/migrations/999_view_replace.sql "CREATE VIEW leak AS SELECT replace('192x168x77x9','x','.') AS ip;"
expect_failure sql-view-parenthesized-alias siem/migrations/999_view_paren.sql "CREATE VIEW leak AS SELECT ('family-nas') AS hostname;"
expect_failure sql-view-bare-alias siem/migrations/999_view_bare.sql "CREATE VIEW leak AS SELECT 'family-nas' hostname;"
expect_failure sql-view-column-list siem/migrations/999_view_columns.sql "CREATE VIEW leak(hostname) AS SELECT 'family-nas';"
expect_failure sql-update-id-type-where siem/migrations/999_id_where.sql "UPDATE facts SET id_value='family-nas' WHERE id_type='hostname';"
expect_failure sql-update-field-where siem/migrations/999_field_where.sql "UPDATE facts SET value='family-nas' WHERE field='hostname';"
expect_failure sql-update-observable-where siem/migrations/999_observable_where.sql "UPDATE facts SET observable_value='192.168.77.9' WHERE observable_type='destination_ip';"
expect_failure sql-char-exponent siem/migrations/999_char_exponent.sql "INSERT INTO devices(mac) VALUES(char(48e0,50e0,49e0,49e0,50e0,50e0,51e0,51e0,52e0,52e0,53e0,53e0));"
expect_failure sql-char-digit-separator siem/migrations/999_char_separator.sql "INSERT INTO devices(mac) VALUES(char(4_8,5_0,4_9,4_9,5_0,5_0,5_1,5_1,5_2,5_2,5_3,5_3));"
expect_failure sql-char-trailing-decimal siem/migrations/999_char_decimal.sql "INSERT INTO devices(mac) VALUES(char(48.,50.,49.,49.,50.,50.,51.,51.,52.,52.,53.,53.));"
expect_failure sql-default-blob-cast siem/migrations/999_blob_cast.sql "CREATE TABLE devices(mac TEXT DEFAULT CAST(X'303231313232333334343535' AS TEXT));"

sql_host_char='char(102,97,109,105,108,121,45,110,97,115)'
quoted_host_constructor() {
  quoted_open="$1"
  quoted_close="$2"
  awk -v quoted_open="$quoted_open" -v quoted_close="$quoted_close" 'BEGIN {
    split("102 97 109 105 108 121 45 110 97 115", lengths)
    printf "%schar%s(", quoted_open, quoted_close
    for (i = 1; i <= 10; i++) {
      if (i > 1) printf ","
      printf "%slength%s(\047", quoted_open, quoted_close
      for (j = 0; j < lengths[i]; j++) printf "."
      printf "\047)"
    }
    printf ")"
  }'
}
sql_bracket_host_constructor="$(quoted_host_constructor '[' ']')"
sql_backtick_host_constructor="$(quoted_host_constructor '`' '`')"
sql_double_host_constructor="$(quoted_host_constructor '"' '"')"
for quoted_call in bracket backtick double; do
  case "$quoted_call" in
    bracket) quoted_constructor="$sql_bracket_host_constructor" ;;
    backtick) quoted_constructor="$sql_backtick_host_constructor" ;;
    double) quoted_constructor="$sql_double_host_constructor" ;;
  esac
  expect_failure "sql-${quoted_call}-quoted-call-insert" \
    "siem/migrations/999_${quoted_call}_call_insert.sql" \
    "INSERT INTO devices(hostname) VALUES($quoted_constructor);"
  expect_failure "sql-${quoted_call}-quoted-call-select" \
    "siem/migrations/999_${quoted_call}_call_select.sql" \
    "CREATE VIEW leak AS SELECT $quoted_constructor AS hostname;"
done
expect_failure sql-empty-constructor-insert siem/migrations/999_empty_insert.sql "INSERT INTO devices(hostname) VALUES(typeof(''));"
expect_failure sql-empty-constructor-update siem/migrations/999_empty_update.sql "UPDATE devices SET hostname=typeof('');"
expect_failure sql-empty-constructor-default siem/migrations/999_empty_default.sql "CREATE TABLE devices(hostname TEXT DEFAULT(typeof('')));"
expect_failure sql-empty-constructor-check siem/migrations/999_empty_check.sql "CREATE TABLE devices(hostname TEXT CHECK(hostname<>typeof('')));"
expect_failure sql-empty-constructor-generated siem/migrations/999_empty_generated.sql "CREATE TABLE devices(x TEXT, hostname TEXT GENERATED ALWAYS AS (typeof('')) STORED);"
expect_failure sql-empty-constructor-view siem/migrations/999_empty_view.sql "CREATE VIEW leak AS SELECT typeof('') AS hostname;"
expect_failure sql-empty-constructor-cte-alias siem/migrations/999_empty_cte_alias.sql "WITH leak AS (SELECT $sql_host_char AS hostname) SELECT * FROM leak;"
expect_failure sql-empty-constructor-cte-columns siem/migrations/999_empty_cte_columns.sql "WITH leak(hostname) AS (VALUES(typeof(''))) SELECT * FROM leak;"
expect_failure sql-empty-constructor-returning siem/migrations/999_empty_returning.sql "INSERT INTO devices(x) VALUES('') RETURNING typeof('') AS hostname;"
expect_failure sql-empty-constructor-index siem/migrations/999_empty_index.sql "CREATE INDEX leak ON devices(x) WHERE hostname=typeof('');"
expect_failure sql-empty-constructor-trigger siem/migrations/999_empty_trigger.sql "CREATE TRIGGER leak AFTER INSERT ON devices BEGIN UPDATE devices SET hostname=typeof(''); END;"
expect_failure sql-true-bitshift-constructor siem/migrations/999_true_shift.sql "INSERT INTO devices(hostname) VALUES(char((TRUE<<TRUE<<TRUE<<TRUE<<TRUE<<TRUE<<TRUE)+(TRUE<<TRUE<<TRUE<<TRUE<<TRUE<<TRUE)+TRUE)||'');"
expect_failure sql-empty-comparison-constructor siem/migrations/999_empty_comparison.sql "INSERT INTO devices(hostname) VALUES((''='')||'');"
expect_failure sql-multiplication-constructor siem/migrations/999_multiplication.sql 'CREATE VIEW leak AS SELECT left_part*right_part AS hostname FROM parts;'
expect_failure sql-single-quoted-column-default siem/migrations/999_single_default.sql \
  "CREATE TABLE t('hostname' TEXT DEFAULT($sql_host_char));"
expect_failure sql-single-quoted-select-alias siem/migrations/999_single_alias.sql \
  "CREATE VIEW v AS SELECT $sql_host_char AS 'hostname';"
expect_failure sql-single-quoted-view-columns siem/migrations/999_single_view.sql \
  "CREATE VIEW v('hostname') AS SELECT $sql_host_char;"
expect_failure sql-single-quoted-ctas-alias siem/migrations/999_single_ctas.sql \
  "CREATE TABLE t AS SELECT $sql_host_char AS 'hostname';"
expect_failure sql-single-quoted-cte-alias siem/migrations/999_single_cte_alias.sql \
  "WITH v AS (SELECT $sql_host_char AS 'hostname') SELECT * FROM v;"
expect_failure sql-single-quoted-cte-columns siem/migrations/999_single_cte_columns.sql \
  "WITH v('hostname') AS (VALUES($sql_host_char)) SELECT * FROM v;"
expect_failure sql-single-quoted-generated siem/migrations/999_single_generated.sql \
  "CREATE TABLE t(x TEXT, 'hostname' TEXT GENERATED ALWAYS AS ($sql_host_char) STORED);"
expect_failure sql-generated-shorthand siem/migrations/999_generated_shorthand.sql \
  "CREATE TABLE t(x INT, hostname AS ($sql_host_char));"
expect_failure sql-generated-typed-shorthand siem/migrations/999_generated_typed_shorthand.sql \
  "CREATE TABLE t(x INT, hostname TEXT AS ($sql_host_char) VIRTUAL);"

expect_failure sql-bracket-default-constructor siem/migrations/999_bracket_default.sql "CREATE TABLE devices([hostname] TEXT DEFAULT($sql_host_char));"
expect_failure sql-backtick-generated-constructor siem/migrations/999_backtick_generated.sql "CREATE TABLE devices(x TEXT, \`hostname\` TEXT GENERATED ALWAYS AS ($sql_host_char) STORED);"
expect_failure sql-bracket-view-constructor siem/migrations/999_bracket_view.sql "CREATE VIEW leak AS SELECT $sql_host_char AS [hostname];"
expect_failure sql-bracket-returning-constructor siem/migrations/999_bracket_returning.sql "INSERT INTO devices(x) VALUES('') RETURNING $sql_host_char AS [hostname];"
expect_failure sql-bracket-index-constructor siem/migrations/999_bracket_index.sql "CREATE INDEX leak ON devices(x) WHERE [hostname]=$sql_host_char;"
expect_success sql-quoted-column-schema siem/migrations/999_quoted_schema.sql 'CREATE TABLE devices("hostname" TEXT);'
expect_success sql-length-check siem/migrations/999_length_check.sql 'CREATE TABLE devices(hostname TEXT CHECK(length(hostname)<=253));'
expect_success sql-length-partial-index siem/migrations/999_length_index.sql 'CREATE INDEX hostname_length ON devices(hostname) WHERE length(hostname)<=253;'
expect_success sql-view-structural-copy siem/migrations/999_view_copy.sql 'CREATE VIEW v(hostname) AS SELECT hostname FROM devices;'
expect_success sql-cte-structural-copy siem/migrations/999_cte_copy.sql 'WITH v(id_type,id_value) AS (SELECT id_type,id_value FROM facts) SELECT * FROM v;'
expect_success sql-ctas-structural-copy siem/migrations/999_ctas_copy.sql \
  'CREATE TABLE v AS SELECT hostname AS hostname FROM devices;'
expect_failure sql-view-aggregate-laundering siem/migrations/999_view_aggregate.sql \
  "CREATE VIEW v(hostname) AS SELECT group_concat(model,'') FROM devices;"
expect_failure sql-cte-aggregate-laundering siem/migrations/999_cte_aggregate.sql \
  "WITH v(hostname) AS (SELECT group_concat(model,'') FROM devices) SELECT * FROM v;"
expect_failure sql-ctas-aggregate-laundering siem/migrations/999_ctas_aggregate.sql \
  "CREATE TABLE v AS SELECT group_concat(model,'') AS hostname FROM devices;"

for relational_pair in \
  attribute:value attribute:value_end id_type:id_value address_type:address_value \
  field:value field:value_end observable_type:observable_value \
  primary_observable_type:primary_observable indicator_type:indicator; do
  relational_type="${relational_pair%%:*}"
  relational_value="${relational_pair#*:}"
  expect_failure "sql-relational-${relational_type}-${relational_value}" \
    "siem/migrations/999_relational_${relational_type}_${relational_value}.sql" \
    "DELETE FROM facts WHERE $relational_type='hostname' AND $relational_value IN ('family-nas');"
  expect_failure "sql-relational-coalesce-predicate-${relational_type}-${relational_value}" \
    "siem/migrations/999_relational_coalesce_predicate_${relational_type}_${relational_value}.sql" \
    "DELETE FROM facts WHERE $relational_type='hostname' AND $relational_value=coalesce('family-nas',NULL);"
  expect_failure "sql-relational-coalesce-update-${relational_type}-${relational_value}" \
    "siem/migrations/999_relational_coalesce_update_${relational_type}_${relational_value}.sql" \
    "UPDATE facts SET $relational_value=coalesce('family-nas',NULL) WHERE $relational_type='hostname';"
done
expect_failure sql-direct-coalesce-where siem/migrations/999_direct_coalesce.sql \
  "DELETE FROM devices WHERE hostname=coalesce('family-nas',NULL);"
expect_failure sql-integer-coalesce-ip siem/migrations/999_integer_coalesce_ip.sql \
  "SELECT source_ip=coalesce(3232255233,NULL) FROM events;"
expect_failure sql-integer-coalesce-mac siem/migrations/999_integer_coalesce_mac.sql \
  "SELECT mac=coalesce(2272611484757,NULL) FROM devices;"
expect_failure sql-coalesce-check siem/migrations/999_coalesce_check.sql \
  "CREATE TABLE t(hostname TEXT CHECK(hostname<>coalesce('family-nas',NULL)));"
expect_failure sql-coalesce-join siem/migrations/999_coalesce_join.sql \
  "SELECT * FROM devices a JOIN devices b ON a.hostname=coalesce('family-nas',NULL);"
expect_failure sql-coalesce-having siem/migrations/999_coalesce_having.sql \
  "SELECT hostname FROM devices GROUP BY hostname HAVING hostname=coalesce('family-nas',NULL);"
expect_failure sql-coalesce-index siem/migrations/999_coalesce_index.sql \
  "CREATE INDEX leak ON devices(hostname) WHERE hostname=coalesce('family-nas',NULL);"
expect_failure sql-coalesce-trigger-when siem/migrations/999_coalesce_trigger.sql \
  "CREATE TRIGGER leak BEFORE INSERT ON devices WHEN NEW.hostname=coalesce('family-nas',NULL) BEGIN SELECT 1; END;"
expect_success sql-copy-only-coalesce-view siem/migrations/999_copy_coalesce.sql \
  "CREATE VIEW v AS SELECT coalesce(hostname,'') AS hostname FROM devices;"
expect_failure sql-relational-like siem/migrations/999_relational_like.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value LIKE 'family-nas';"
expect_failure sql-relational-glob siem/migrations/999_relational_glob.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value GLOB 'family-nas';"
expect_failure sql-relational-match siem/migrations/999_relational_match.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value MATCH 'family-nas';"
expect_failure sql-relational-regexp siem/migrations/999_relational_regexp.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value REGEXP 'family-nas';"
expect_failure sql-relational-is siem/migrations/999_relational_is.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value IS 'family-nas';"
expect_failure sql-relational-not-equal siem/migrations/999_relational_ne.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value != 'family-nas';"
expect_failure sql-relational-angle-not-equal siem/migrations/999_relational_angle_ne.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value <> 'family-nas';"
expect_failure sql-relational-between siem/migrations/999_relational_between.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value BETWEEN 'family-nas' AND 'family-nas-z';"
expect_failure sql-relational-less-than siem/migrations/999_relational_lt.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value < 'family-nas';"
expect_failure sql-relational-constructor siem/migrations/999_relational_constructor.sql "DELETE FROM facts WHERE id_type='hostname' AND id_value=$sql_host_char;"
expect_failure sql-relational-split-line-comments siem/migrations/999_relational_line_comments.sql $'-- id_type=hostname\n-- id_value=family-nas'
expect_failure sql-relational-split-block-comments siem/migrations/999_relational_block_comments.sql '/* id_type=hostname */ /* id_value=family-nas */'
expect_failure sql-relational-colon-line-comments siem/migrations/999_relational_colon.sql $'-- attribute: hostname\n-- value: family-nas'
expect_failure sql-relational-colon-id-comments siem/migrations/999_relational_colon_id.sql $'-- id_type: hostname\n-- id_value: family-nas'
expect_failure sql-relational-json-comment siem/migrations/999_relational_json_comment.sql '-- {"attribute":"hostname","value":"family-nas"}'
expect_failure sql-relational-colon-block-comments siem/migrations/999_relational_colon_block.sql '/* observable_type: destination_ip */ /* observable_value: 192.168.77.9 */'
expect_failure sql-relational-defaults siem/migrations/999_relational_defaults.sql "CREATE TABLE facts(id_type TEXT DEFAULT 'hostname', id_value TEXT DEFAULT 'family-nas');"
expect_failure sql-relational-check siem/migrations/999_relational_check.sql "CREATE TABLE facts(id_type TEXT, id_value TEXT, CHECK(id_type<>'hostname' OR id_value<>'family-nas'));"
expect_failure sql-relational-generated siem/migrations/999_relational_generated.sql "CREATE TABLE facts(id_type TEXT DEFAULT 'hostname', x TEXT, id_value TEXT GENERATED ALWAYS AS ('family-nas') STORED);"
expect_failure sql-relational-view siem/migrations/999_relational_view.sql "CREATE VIEW leak(id_type,id_value) AS SELECT 'hostname','family-nas';"
expect_failure sql-relational-cte siem/migrations/999_relational_cte.sql "WITH leak(id_type,id_value) AS (VALUES('hostname','family-nas')) SELECT * FROM leak;"
expect_failure sql-relational-returning siem/migrations/999_relational_returning.sql "DELETE FROM facts RETURNING 'hostname' AS id_type,'family-nas' AS id_value;"
expect_failure sql-relational-partial-index siem/migrations/999_relational_partial.sql "CREATE INDEX leak ON facts(x) WHERE id_type='hostname' AND id_value!='family-nas';"

expect_failure sql-join-on-constructor siem/migrations/999_join_on.sql "SELECT * FROM devices d JOIN devices e ON d.hostname=$sql_host_char;"
expect_failure sql-join-on-relational siem/migrations/999_join_relational.sql "SELECT * FROM facts a JOIN facts b ON a.id_type='hostname' AND a.id_value IN ('family-nas');"
expect_failure sql-having-constructor siem/migrations/999_having.sql "SELECT hostname FROM devices GROUP BY hostname HAVING hostname=$sql_host_char;"
expect_failure sql-having-relational siem/migrations/999_having_relational.sql "SELECT id_type,id_value FROM facts GROUP BY id_type,id_value HAVING id_type='hostname' AND id_value!='family-nas';"
expect_failure sql-select-predicate-constructor siem/migrations/999_select_predicate.sql \
  "SELECT hostname=$sql_host_char FROM devices;"
expect_failure sql-case-predicate-constructor siem/migrations/999_case_predicate.sql \
  "SELECT CASE WHEN hostname=$sql_host_char THEN 1 ELSE 0 END FROM devices;"
expect_failure sql-nested-where-constructor siem/migrations/999_nested_where.sql \
  "SELECT (SELECT 1 WHERE hostname=$sql_host_char) FROM devices;"
expect_failure sql-order-by-constructor siem/migrations/999_order_by.sql \
  "SELECT hostname FROM devices ORDER BY hostname=$sql_host_char;"
expect_failure sql-group-by-constructor siem/migrations/999_group_by.sql \
  "SELECT count(*) FROM devices GROUP BY hostname=$sql_host_char;"
expect_failure sql-window-order-constructor siem/migrations/999_window_order.sql \
  "SELECT row_number() OVER (ORDER BY hostname=$sql_host_char) FROM devices;"
expect_failure sql-filter-where-constructor siem/migrations/999_filter_where.sql \
  "SELECT count(*) FILTER (WHERE hostname=$sql_host_char) FROM devices;"
expect_failure sql-exists-where-constructor siem/migrations/999_exists_where.sql \
  "SELECT EXISTS(SELECT 1 FROM devices WHERE hostname=$sql_host_char);"
expect_failure sql-index-case-constructor siem/migrations/999_index_case.sql \
  "CREATE INDEX leak ON devices((CASE WHEN hostname=$sql_host_char THEN 1 ELSE 0 END));"
expect_failure sql-index-coalesce-constructor siem/migrations/999_index_coalesce.sql \
  "CREATE INDEX leak ON devices(coalesce(hostname,$sql_host_char));"

expect_failure sql-reverse-equals siem/migrations/999_reverse_equals.sql \
  "SELECT * FROM devices WHERE 'router.example'=hostname;"
expect_failure sql-reverse-is siem/migrations/999_reverse_is.sql \
  "SELECT * FROM devices WHERE 'router.example' IS hostname;"
expect_failure sql-reverse-glob siem/migrations/999_reverse_glob.sql \
  "SELECT * FROM devices WHERE 'router.example' GLOB hostname;"
expect_failure sql-reverse-match siem/migrations/999_reverse_match.sql \
  "SELECT * FROM devices WHERE 'router.example' MATCH hostname;"
expect_failure sql-reverse-regexp siem/migrations/999_reverse_regexp.sql \
  "SELECT * FROM devices WHERE 'router.example' REGEXP hostname;"
expect_failure sql-reverse-in siem/migrations/999_reverse_in.sql \
  "SELECT * FROM devices WHERE 'router.example' IN (hostname);"
expect_failure sql-reverse-check siem/migrations/999_reverse_check.sql \
  "CREATE TABLE t(hostname TEXT, CHECK('router.example'=hostname));"
expect_failure sql-reverse-field-attached-check siem/migrations/999_reverse_field_check.sql \
  "CREATE TABLE t(attribute TEXT CHECK('router.example'=hostname), hostname TEXT);"
expect_failure sql-reverse-untyped-field-check siem/migrations/999_reverse_untyped_check.sql \
  "CREATE TABLE t(hostname TEXT, notes TEXT CHECK('router.example'=hostname));"
expect_failure sql-reverse-alter-field-check siem/migrations/999_reverse_alter_check.sql \
  "ALTER TABLE devices ADD notes TEXT CHECK('router.example'=hostname);"
expect_failure sql-reverse-untyped-generated siem/migrations/999_reverse_generated.sql \
  "CREATE TABLE t(hostname TEXT, flag INT AS (CASE WHEN 'router.example'=hostname THEN 1 ELSE 0 END));"
expect_failure sql-reverse-trigger-when siem/migrations/999_reverse_trigger.sql \
  "CREATE TRIGGER leak BEFORE INSERT ON devices WHEN 'router.example' IS NEW.hostname BEGIN SELECT 1; END;"
expect_failure sql-reverse-index-expression siem/migrations/999_reverse_index.sql \
  "CREATE INDEX leak ON devices((CASE WHEN 'router.example' GLOB hostname THEN 1 ELSE 0 END));"
expect_failure sql-length-index-exemption-smuggling siem/migrations/999_length_index_smuggle.sql \
  "CREATE INDEX leak ON devices((CASE WHEN 'router.example'=hostname THEN 1 ELSE 0 END)) WHERE length(hostname)<=253;"
expect_failure sql-reverse-order-expression siem/migrations/999_reverse_order.sql \
  "SELECT hostname FROM devices ORDER BY 'router.example' MATCH hostname;"
expect_failure sql-reverse-case-expression siem/migrations/999_reverse_case.sql \
  "SELECT CASE WHEN 'router.example' REGEXP hostname THEN hostname END FROM devices;"
expect_failure sql-reverse-window-expression siem/migrations/999_reverse_window.sql \
  "SELECT row_number() OVER (ORDER BY 'router.example'=hostname) FROM devices;"
expect_failure sql-reverse-filter-expression siem/migrations/999_reverse_filter.sql \
  "SELECT count(*) FILTER (WHERE 'router.example' IS hostname) FROM devices;"
expect_failure sql-reverse-exists-expression siem/migrations/999_reverse_exists.sql \
  "SELECT EXISTS(SELECT 1 FROM devices WHERE 'router.example' GLOB hostname);"
expect_failure sql-reverse-nested-select siem/migrations/999_reverse_nested.sql \
  "SELECT (SELECT 'router.example'=hostname) FROM devices;"
expect_failure sql-reverse-keyword-literal siem/migrations/999_reverse_keyword.sql \
  "SELECT TRUE=hostname FROM devices;"
expect_failure sql-explain-query-plan-reverse siem/migrations/999_explain_reverse.sql \
  "EXPLAIN QUERY PLAN SELECT * FROM devices WHERE 'router.example'=hostname;"

expect_failure sql-parenthesized-comparison siem/migrations/999_parenthesized_comparison.sql \
  "SELECT * FROM devices WHERE (hostname)='family-nas';"
expect_failure sql-double-equals-comparison siem/migrations/999_double_equals.sql \
  "SELECT * FROM devices WHERE hostname=='family-nas';"
expect_failure sql-collate-comparison siem/migrations/999_collate_comparison.sql \
  "SELECT * FROM devices WHERE hostname COLLATE binary='family-nas';"
expect_failure sql-concat-comparison siem/migrations/999_concat_comparison.sql \
  "SELECT * FROM devices WHERE hostname||''='family-nas';"
expect_failure sql-relational-double-equals siem/migrations/999_relational_double_equals.sql \
  "SELECT * FROM facts WHERE id_type=='hostname' AND id_value=='family-nas';"
expect_failure sql-literal-left-like siem/migrations/999_literal_left_like.sql \
  "SELECT * FROM devices WHERE 'family-nas' LIKE hostname;"
expect_failure sql-not-like siem/migrations/999_not_like.sql \
  "SELECT * FROM devices WHERE hostname NOT LIKE 'family-nas';"
expect_failure sql-not-in siem/migrations/999_not_in.sql \
  "SELECT * FROM devices WHERE hostname NOT IN ('family-nas');"
expect_failure sql-is-distinct-from siem/migrations/999_is_distinct.sql \
  "SELECT * FROM devices WHERE hostname IS DISTINCT FROM 'family-nas';"

quoted_sql_punctuation="$(awk 'BEGIN { printf "--"; for (i = 0; i < 20001; i++) printf ";"; for (i = 0; i < 8193; i++) printf "\047"; for (i = 0; i < 16385; i++) printf "("; for (i = 0; i < 100001; i++) printf "," }')"
expect_success sql-comment-punctuation-limits siem/migrations/999_comment_limits.sql "$quoted_sql_punctuation"
literal_semicolons="$(awk 'BEGIN { printf "SELECT \047"; for (i = 0; i < 20001; i++) printf ";"; printf "\047;" }')"
expect_success sql-literal-semicolon-limit siem/migrations/999_literal_semicolons.sql "$literal_semicolons"
oversized_sql="--$(awk 'BEGIN { for (i = 0; i < 262145; i++) printf "a" }')"
expect_failure sql-byte-limit siem/migrations/999_byte_limit.sql "$oversized_sql"
new_repo json-utf8-byte-limit
python3 - "$repo/specs/999-sanitize/contracts/fixtures/multibyte.json" <<'PY'
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(
    '{"notes":"' + ('é' * 600_000) + '"}\n', encoding="utf-8"
)
PY
git -C "$repo" add -f .
assert_failure json-utf8-byte-limit \
  specs/999-sanitize/contracts/fixtures/multibyte.json "$repo"
if ! printf '%s' "$failure_output" | grep -F \
  'structured data exceeds its safe parser limit' >/dev/null; then
  printf 'FAIL: multibyte JSON did not trip the UTF-8 byte limit\n%s\n' \
    "$failure_output" >&2
  exit 1
fi
select_keyword_bomb="$(awk 'BEGIN { while (n < 32768) { printf "select "; n += 7 } }')"
expect_fast_failure sql-select-keyword-cap siem/migrations/999_select_keyword_cap.sql \
  "$select_keyword_bomb" 3000
clause_keyword_bomb="$(awk 'BEGIN { while (n < 32768) { printf "join on having "; n += 15 } }')"
expect_fast_failure sql-clause-keyword-cap siem/migrations/999_clause_keyword_cap.sql \
  "$clause_keyword_bomb" 3000

expect_success public-product corpus/device_models.json '{"product_name":"Living Room TV","manufacturer":"Example Vendor"}'
expect_success telemetry-export-source telemetry/internal/export/new.go 'package export'
expect_failure telemetry-export-uppercase-source telemetry/internal/export/new.GO 'package export'
expect_failure telemetry-export-blob telemetry/internal/export/leak.bin 'opaque export data'
expect_failure telemetry-export-nested-source telemetry/internal/export/generated/leak.go 'package export'
if git -C "$source_root" check-ignore -q --no-index telemetry/internal/export/new.go; then
  printf 'FAIL: .gitignore hides direct telemetry export Go source\n' >&2
  exit 1
fi
if ! git -C "$source_root" -c core.ignorecase=false check-ignore -q --no-index \
  telemetry/internal/export/new.GO; then
  printf 'FAIL: .gitignore exposes uppercase telemetry export source on case-sensitive Git\n' >&2
  exit 1
fi
for ignored_export_path in \
  telemetry/internal/export/leak.bin \
  telemetry/internal/export/generated/leak.go \
  telemetry/internal/export/generated.go/leak.bin \
  telemetry/internal/export/generated.go/nested.go; do
  if ! git -C "$source_root" check-ignore -q --no-index "$ignored_export_path"; then
    printf 'FAIL: .gitignore exposes non-source telemetry export path %s\n' \
      "$ignored_export_path" >&2
    exit 1
  fi
done
# Git's ignore matching follows core.ignorecase on case-insensitive worktrees,
# so `.GO` may share the lowercase negation there. The policy gate above is the
# cross-platform authority and must reject every non-lowercase source suffix.
expect_failure lfs-pointer corpus/devices.dat 'version https://git-lfs.github.com/spec/v1
oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
size 12345'
expect_failure root-lfs-pointer fingerprints.bin 'version https://git-lfs.github.com/spec/v1
oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
size 12345'
expect_failure legacy-lfs-pointer asset.bin 'version https://hawser.github.com/spec/v1
oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
size 12345'
expect_failure crlf-lfs-pointer asset.bin $'version https://git-lfs.github.com/spec/v1\r\noid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\nsize 12345\r'
expect_success lfs-prefix-not-pointer asset.bin $'version https://git-lfs.github.com/spec/v1\r\noid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\nsize 12345\r\nnot-a-pointer'

new_repo data-symlink
ln -s /etc/hosts "$repo/specs/999-sanitize/contracts/fixtures/hosts.txt"
git -C "$repo" add -f .
assert_failure data-symlink specs/999-sanitize/contracts/fixtures/hosts.txt "$repo"

new_repo broad-inventory-symlink
mkdir -p "$repo/inventory-prod"
ln -s /etc/hosts "$repo/inventory-prod/hosts.txt"
git -C "$repo" add -f .
assert_failure broad-inventory-symlink inventory-prod/hosts.txt "$repo"

new_repo telemetry-export-source-symlink
mkdir -p "$repo/telemetry/internal/export"
ln -s /etc/hosts "$repo/telemetry/internal/export/leak.go"
git -C "$repo" add -f .
assert_failure telemetry-export-source-symlink telemetry/internal/export/leak.go "$repo"

new_repo ordinary-symlink
ln -s /Users/operator/lab/camera-capture.pcap "$repo/README.md"
git -C "$repo" add -f .
assert_failure ordinary-symlink README.md "$repo"
if printf '%s' "$failure_output" | grep -F '/Users/operator/lab' >/dev/null; then
  printf 'FAIL: sanitation disclosed an ordinary symlink target\n%s\n' "$failure_output" >&2
  exit 1
fi

new_repo safe-target-symlink
mkdir -p "$repo/docs"
printf '%s\n' 'synthetic documentation' > "$repo/docs/guide.md"
ln -s docs/guide.md "$repo/GUIDE.md"
git -C "$repo" add -f .
assert_failure safe-target-symlink GUIDE.md "$repo"

new_repo staged-gitlink
git -C "$repo" add -f .
git -C "$repo" commit -q -m clean
gitlink_oid="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" update-index --add --cacheinfo "160000,$gitlink_oid,modules/family-nas.local"
assert_failure staged-gitlink tracked-path# "$repo"
if printf '%s' "$failure_output" | grep -F 'family-nas.local' >/dev/null; then
  printf 'FAIL: sanitation disclosed an identifier-bearing gitlink path\n%s\n' "$failure_output" >&2
  exit 1
fi

new_repo committed-gitlink-history
git -C "$repo" add -f .
git -C "$repo" commit -q -m clean
gitlink_base="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" update-index --add --cacheinfo "160000,$gitlink_base,plugins/device-corpus"
git -C "$repo" commit -q -m 'add synthetic gitlink'
git -C "$repo" update-index --force-remove plugins/device-corpus
git -C "$repo" commit -q -m 'remove synthetic gitlink'
"$check" "$repo" >/dev/null
assert_failure committed-gitlink-history plugins/device-corpus "$repo" --history-range "$gitlink_base..HEAD"

# Identifiers in a filename are repository data too. Diagnostics must give a
# stable local-remediation hash without republishing the raw tracked path.
new_repo identifier-path
identifier_path='corpus/192.168.77.9-family-nas.local-021122334455.json'
mkdir -p "$(dirname -- "$repo/$identifier_path")"
printf '%s\n' '{}' > "$repo/$identifier_path"
git -C "$repo" add -f .
set +e
failure_output="$("$check" "$repo" 2>&1)"
status=$?
set -e
if [ "$status" -ne 1 ] || ! printf '%s' "$failure_output" | grep -F 'tracked-path#' >/dev/null; then
  printf 'FAIL: sanitation did not reject/hash an identifier-bearing path\n%s\n' "$failure_output" >&2
  exit 1
fi
for identifier in '192.168.77.9' 'family-nas.local' '021122334455'; do
  if printf '%s' "$failure_output" | grep -F "$identifier" >/dev/null; then
    printf 'FAIL: sanitation diagnostics disclosed identifier-bearing path data\n%s\n' "$failure_output" >&2
    exit 1
  fi
done

for path_case in clean failing; do
  new_repo "extension-path-$path_case"
  extension_path='corpus/router.192.168.77.9.json'
  mkdir -p "$(dirname -- "$repo/$extension_path")"
  if [ "$path_case" = clean ]; then
    printf '%s\n' '{}' > "$repo/$extension_path"
  else
    printf '%s\n' '{"host":"another-family-device.local"}' > "$repo/$extension_path"
  fi
  git -C "$repo" add -f .
  set +e
  failure_output="$("$check" "$repo" 2>&1)"
  status=$?
  set -e
  if [ "$status" -ne 1 ] || ! printf '%s' "$failure_output" | grep -F 'tracked-path#' >/dev/null; then
    printf 'FAIL: sanitation did not reject/hash extension-bearing path (%s)\n%s\n' "$path_case" "$failure_output" >&2
    exit 1
  fi
  if printf '%s' "$failure_output" | grep -F '192.168.77.9' >/dev/null; then
    printf 'FAIL: sanitation disclosed extension-bearing path (%s)\n%s\n' "$path_case" "$failure_output" >&2
    exit 1
  fi
done

show_paths_output="$("$check" "$repo" --show-paths 2>&1 || true)"
case "$show_paths_output" in
  *'tracked-path#'*'corpus/router.192.168.77.9.json'*) ;;
  *)
    printf 'FAIL: local --show-paths did not map ordinal to raw path\n%s\n' "$show_paths_output" >&2
    exit 1
    ;;
esac

new_repo oversized-data
truncate -s $((8 * 1024 * 1024 + 1)) "$repo/specs/999-sanitize/contracts/fixtures/oversized.txt"
git -C "$repo" add -f .
assert_failure oversized-data specs/999-sanitize/contracts/fixtures/oversized.txt "$repo"

# The default scan must read the immutable staged blob rather than a different
# worktree version. This is what makes the pre-commit/deploy check race-free.
new_repo staged-index
git -C "$repo" add -f .
index_path='specs/999-sanitize/contracts/fixtures/clean.json'
printf '%s\n' '{"ip":"192.168.66.10"}' > "$repo/$index_path"
"$check" "$repo" >/dev/null
git -C "$repo" add -f "$index_path"
assert_failure staged-index "$index_path" "$repo"

# A leak that is added and then deleted still exists in the commits a PR or
# deployment publishes. The index at HEAD is clean, so only the history-range
# scan can catch this regression.
new_repo add-delete-history
git -C "$repo" add -f .
git -C "$repo" commit -q -m clean
clean_commit="$(git -C "$repo" rev-parse HEAD)"
history_path='specs/999-sanitize/contracts/fixtures/transient-leak.json'
printf '%s\n' '{"ip":"192.168.88.23"}' > "$repo/$history_path"
git -C "$repo" add -f "$history_path"
git -C "$repo" commit -q -m 'add transient fixture'
rm "$repo/$history_path"
git -C "$repo" add -u
git -C "$repo" commit -q -m 'remove transient fixture'
"$check" "$repo" >/dev/null
assert_failure add-delete-history "$history_path" "$repo" --history-range "$clean_commit..HEAD"
assert_failure recreated-default-history "$history_path" "$repo" --history-range HEAD

# The embedded IEEE OUI table is public reference data exempted from the identity scans:
# real vendor names such as "MFG.CORP." look like hostnames but must be accepted, while
# the table's structural contract (a prefix,vendor header + 6-hex prefixes) is enforced.
oui_table_path='backend/internal/fingerprint/data/oui.csv'
expect_success oui-table-public-vendors "$oui_table_path" \
  'prefix,vendor
000000,XEROX CORPORATION
00abcd,"CHUNG-HSIN ELECTRIC & MACHINERY MFG.CORP."
acbc32,"Apple, Inc."'
expect_failure oui-table-nonhex-prefix "$oui_table_path" \
  'prefix,vendor
nothex,Bogus Vendor'
expect_failure oui-table-wrong-header "$oui_table_path" \
  'mac,vendor
acbc32,Apple'

printf 'repo sanitation tests passed\n'
