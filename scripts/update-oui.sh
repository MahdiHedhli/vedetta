#!/usr/bin/env bash
#
# update-oui.sh — refresh the embedded IEEE MA-L (24-bit OUI) vendor table.
#
# Clean-room implementation (no third-party code). Downloads the authoritative IEEE
# registry CSV, normalizes it to the compact "prefix,vendor" shape that
# backend/internal/fingerprint/oui_ieee.go embeds via go:embed, and writes it in place.
# The monthly update-oui workflow runs this and opens a PR when the table changes; it
# never pushes to a branch directly.
#
# Exit codes (the workflow branches on these):
#   0  table updated (content changed) — caller should commit / open a PR
#   3  no change (already current)     — not an error, nothing to do
#   1  failure (download, validation, or transform error)
#
# Env overrides (mainly for testing; production uses the defaults):
#   OUI_SOURCE_URL      source URL (default: IEEE). curl-compatible, so file:// works.
#   OUI_OUTPUT_PATH     destination CSV (default: the embedded table in this repo).
#   OUI_MIN_RAW_BYTES   minimum plausible download size (default 1000000).
#   OUI_MIN_ROWS        minimum plausible normalized row count (default 30000).

set -euo pipefail

readonly EXIT_UPDATED=0
readonly EXIT_ERROR=1
readonly EXIT_NOCHANGE=3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SOURCE_URL="${OUI_SOURCE_URL:-https://standards-oui.ieee.org/oui/oui.csv}"
OUTPUT_PATH="${OUI_OUTPUT_PATH:-$REPO_ROOT/backend/internal/fingerprint/data/oui.csv}"
MIN_RAW_BYTES="${OUI_MIN_RAW_BYTES:-1000000}"
MIN_ROWS="${OUI_MIN_ROWS:-30000}"

log()  { printf '[update-oui] %s\n' "$*" >&2; }
fail() { log "ERROR: $*"; exit "$EXIT_ERROR"; }

command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v curl    >/dev/null 2>&1 || fail "curl is required"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
raw="$tmpdir/oui-raw.csv"
normalized="$tmpdir/oui-normalized.csv"

log "downloading $SOURCE_URL"
curl -fsSL --retry 3 --retry-delay 5 --max-time 120 -o "$raw" "$SOURCE_URL" \
    || fail "download failed"

# Validate the raw download looks like the IEEE registry CSV before trusting it.
[ -s "$raw" ] || fail "downloaded file is empty"
raw_bytes="$(wc -c < "$raw" | tr -d ' ')"
[ "$raw_bytes" -ge "$MIN_RAW_BYTES" ] || fail "download too small ($raw_bytes bytes, need >= $MIN_RAW_BYTES)"
head -1 "$raw" | grep -q '^Registry,Assignment,Organization Name' \
    || fail "unexpected header — IEEE CSV format may have changed"

# Clean-room normalize: Assignment -> lowercase 6-hex prefix, Organization Name ->
# vendor; drop the header, non-MA-L, and malformed rows; sort ascending; dedupe. The
# writer uses an explicit LF terminator so refresh diffs stay stable across platforms.
python3 - "$raw" "$normalized" <<'PY' || fail "normalize failed"
import csv, sys
src, dst = sys.argv[1], sys.argv[2]
rows = {}
with open(src, newline='', encoding='utf-8', errors='replace') as f:
    reader = csv.reader(f)
    next(reader, None)  # header
    for rec in reader:
        if len(rec) < 3:
            continue
        prefix = rec[1].strip().lower()
        vendor = rec[2].strip()
        if len(prefix) != 6 or any(c not in '0123456789abcdef' for c in prefix):
            continue
        if not vendor:
            continue
        rows[prefix] = vendor
with open(dst, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f, lineterminator='\n')
    w.writerow(['prefix', 'vendor'])
    for prefix in sorted(rows):
        w.writerow([prefix, rows[prefix]])
PY

# Validate the normalized output before letting it replace the committed table.
norm_lines="$(wc -l < "$normalized" | tr -d ' ')"
norm_rows=$(( norm_lines - 1 ))  # minus the header
[ "$norm_rows" -ge "$MIN_ROWS" ] || fail "only $norm_rows rows after normalize (need >= $MIN_ROWS)"
log "normalized $norm_rows OUI entries"

# Compare with the committed table; a byte-identical result means nothing to do.
if [ -f "$OUTPUT_PATH" ] && cmp -s "$normalized" "$OUTPUT_PATH"; then
    log "no change — table already current"
    exit "$EXIT_NOCHANGE"
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
cp "$normalized" "$OUTPUT_PATH"
log "updated $OUTPUT_PATH ($norm_rows entries)"
exit "$EXIT_UPDATED"
