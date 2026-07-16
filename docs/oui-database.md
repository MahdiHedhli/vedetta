# OUI Vendor Database

Vedetta maps a device's MAC-address prefix (the first three octets, the *OUI*) to a
hardware vendor. This is the coarsest device-identity signal — it answers "who made the
NIC," not "what is this device" — but it is cheap, offline, and the foundation the
higher-confidence fingerprint signals build on.

The lookup lives in `backend/internal/fingerprint` and uses IEEE MA-L as the
authoritative OUI source.

## Lookup behavior

`data/oui.csv`, embedded via `go:embed` in `oui_ieee.go`, contains the full public IEEE
24-bit MA-L registry (~39.7k prefixes). It produces vendor-only evidence; device type
requires stronger corroboration from hostname, services, model data, or active probes.

The legacy `ouiDatabase` map remains in `oui.go` for a future audited hint migration,
but it is intentionally not consulted. It contains stale and conflicting assignments,
and before this change its colon-formatted keys never matched the old stripped lookup
key. Enabling those rows would create new false vendor, device-type, and risk labels.

`Engine.Lookup` validates and normalizes the MAC (lowercase, separators stripped),
rejects multicast and locally administered/randomized addresses as non-vendor evidence,
then resolves against IEEE:

| Match          | Vendor            | Device type | Confidence |
| -------------- | ----------------- | ----------- | ---------- |
| IEEE MA-L      | IEEE name         | —           | 0.2        |
| Neither        | *nil*             | —           | —          |

Confidence stays at `0.2` because an OUI match alone is weak — a prefix identifies the
NIC vendor, and a single vendor ships everything from doorbells to servers. The corpus
matcher (a later phase) fuses this with stronger signals.

## Data provenance

`data/oui.csv` is derived from the authoritative IEEE registry at
<https://standards-oui.ieee.org/oui/oui.csv>, which IEEE provides as its downloadable
MA-L public listing. Vedetta normalizes that listing and ships it in-repo and compiled
into the binary — no network call at runtime, no third-party fingerprint service.

The file is the registry normalized to a compact two-column shape:

```csv
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

After signed-updater initialization validates its trust root and configuration, `Lookup`
uses `<VEDETTA_DB_UPDATE_INSTALL_DIR>/oui.csv`. The environment flag/path alone never
activates persisted managed bytes. Outside that validated managed-update configuration, an
explicitly operator-managed table at `VEDETTA_OUI_DB_PATH` takes precedence over the
embedded baseline. Either on-disk table must contain at least 30,000 unique valid MA-L
rows; a missing, tiny, truncated, or unusable table falls back to the embedded registry.
See [Signed Device-DB Releases](device-db-releases.md).
