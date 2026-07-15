# OUI Vendor Database

Vedetta maps a device's MAC-address prefix (the first three octets, the *OUI*) to a
hardware vendor. This is the coarsest device-identity signal — it answers "who made the
NIC," not "what is this device" — but it is cheap, offline, and the foundation the
higher-confidence fingerprint signals build on.

The lookup lives in `backend/internal/fingerprint` and has two layers.

## Layers

1. **Curated overlay** (`ouiDatabase` in `oui.go`) — a hand-maintained set of ~200
   common home/SMB prefixes that also carry a **device-type hint** (`router`, `camera`,
   `smart_speaker`, …) and a cleaned-up vendor name (`"Apple"` rather than
   `"Apple, Inc."`). This is the only source of device-type hints.
2. **IEEE MA-L fallback** (`data/oui.csv`, embedded via `go:embed` in `oui_ieee.go`) —
   the full public IEEE 24-bit OUI registry (~39.7k prefixes), vendor name only, no
   device type.

`Engine.Lookup` normalizes the MAC (lowercase, separators stripped), then resolves
**curated first, IEEE second**:

| Match          | Vendor            | Device type | Confidence |
| -------------- | ----------------- | ----------- | ---------- |
| Curated        | curated name      | hint (may be empty) | 0.2 |
| IEEE fallback  | IEEE name         | —           | 0.2        |
| Neither        | *nil*             | —           | —          |

Confidence stays at `0.2` because an OUI match alone is weak — a prefix identifies the
NIC vendor, and a single vendor ships everything from doorbells to servers. The corpus
matcher (a later phase) fuses this with stronger signals.

> The curated map's literal keys are colon-formatted (`"ac:bc:32"`), so it is normalized
> into a separator-free index once at first use. (Before that index existed the overlay
> silently never matched — see the piece-2 commit.)

## Data provenance & license

`data/oui.csv` is derived from the authoritative IEEE registry at
<https://standards-oui.ieee.org/oui/oui.csv>. The IEEE publishes the OUI/MA-L assignments
for public use and redistribution, so the table ships in-repo and compiled into the
binary — no network call at runtime, no third-party fingerprint service.

The file is the registry normalized to a compact two-column shape:

```
prefix,vendor
000000,XEROX CORPORATION
acbc32,"Apple, Inc."
```

`prefix` is the lowercase 6-hex OUI; `vendor` is the IEEE "Organization Name"
(CSV-quoted when it contains a comma). Rows are sorted and de-duplicated.

## Refreshing the table

The IEEE registry grows over time. Regenerate the embedded copy with:

```sh
scripts/update-oui.sh
```

It downloads the registry, validates it (non-empty, plausible size, expected header),
normalizes it to the shape above, and rewrites `data/oui.csv` **only if the content
changed**. Exit codes:

| Code | Meaning                                           |
| ---- | ------------------------------------------------- |
| `0`  | table updated (content changed) — commit it       |
| `3`  | no change — already current                       |
| `1`  | failure (download, validation, or transform)      |

The transform is deterministic and reproduces the committed file byte-for-byte, so a
no-op run is a true no-op.

### Automation

`.github/workflows/update-oui.yml` runs the script on a monthly cron (and on manual
dispatch). When the table changes it rebuilds the backend and runs the fingerprint tests,
then opens — or force-refreshes — a single `automation/oui-update` pull request against
`main`. **It never pushes to `main`;** every refresh lands through review.

## Runtime override

`Lookup` prefers an on-disk table at `VEDETTA_OUI_DB_PATH` over the embedded baseline,
falling back to the baseline if that file is missing or unusable (it is never allowed to
replace the table with an empty one). This is the install path for the signed device-DB
bundle delivered by a later phase; unset, the embedded table is authoritative.
