# Update Notifier

The dashboard can surface a dismissible banner when a newer **Vedetta software release**
(`v*` tag) or **signed device-DB release** (`db-*` tag) is available. It is **read-only** —
it checks a version and shows a notice, and never downloads, verifies, or installs anything.
Applying a device-DB update is a separate, opt-in step (see
[Signed Device-DB Releases](device-db-releases.md)); upgrading Vedetta itself is a manual
operator action.

## Behaviour

- The backend polls the repository's **public** GitHub releases on an interval and caches
  the result. It picks the latest published (non-draft, non-prerelease) `v*` and `db-*`
  tags.
- **Software:** compared against the running build with a `vMAJOR.MINOR.PATCH` check — a
  source/`dev` build is never nagged.
- **Device DB:** the latest `db-*` release is compared against the installed signed
  generation (or "none" if the opt-in updater has never run).
- The dashboard shows a per-channel banner only when an update is available, with a link to
  the release notes (sanitized to an `https` `github.com` URL). Each notice is dismissible
  per release tag, so a brand-new release surfaces again.

## Privacy & default

**On by default, opt-out.** The check is a read-only version poll that reveals only that a
Vedetta instance exists — the same exposure as the community feed — and it is always
disableable. It is independent of the device-DB updater, which stays **off** by default.

| Env var | Default | Meaning |
| ------- | ------- | ------- |
| `VEDETTA_UPDATE_CHECK_ENABLED` | on | Set to the exact value `false` to disable all release checks. |
| `VEDETTA_UPDATE_CHECK_INTERVAL` | `6h` | Poll cadence (Go duration). |
| `VEDETTA_UPDATE_CHECK_REPO` | official repo | `owner/repo` to check releases from. |

When disabled, no release checks are made and `GET /api/v1/update-status` reports
`{"enabled": false}` so the dashboard shows nothing.

## API

`GET /api/v1/update-status` (read scope) returns the cached status:

```json
{
  "enabled": true,
  "checked_at": "2026-07-16T00:00:00Z",
  "software":  { "current": "v1.2.0", "latest": "v1.3.0", "update_available": true, "url": "https://github.com/…" },
  "device_db": { "current": "db-2026.06", "latest": "db-2026.07", "update_available": true, "url": "https://github.com/…" }
}
```
